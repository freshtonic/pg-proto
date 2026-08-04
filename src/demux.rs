//! Filtering projection from backend messages to the typed session stream.

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use crate::codec::{BackendMessage, DiagnosticResponse, TransactionStatus};

/// Position of a command within a connection's session.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct CommandIndex(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
/// A backend notice attributed to the command active when it arrived.
pub struct TaggedNotice {
    /// Command to which the notice belongs.
    pub command: CommandIndex,
    /// Structured notice fields.
    pub fields: DiagnosticResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A decoded asynchronous notification.
pub struct Notification {
    /// Process identifier of the notifying backend.
    pub process_id: u32,
    /// Notification channel.
    pub channel: Bytes,
    /// Notification payload.
    pub payload: Bytes,
}

/// One ordered `ParameterStatus` update retained for proxy forwarding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterStatus {
    /// Parameter name.
    pub name: Bytes,
    /// Current parameter value.
    pub value: Bytes,
}

/// A causally independent backend event retained in its original wire order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AsyncEvent {
    /// A positionally tagged notice.
    Notice(TaggedNotice),
    /// A run-time parameter update.
    ParameterStatus(ParameterStatus),
    /// A `LISTEN`/`NOTIFY` notification.
    Notification(Notification),
}

/// Ordering and command attribution for an asynchronous backend event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedAsyncEvent {
    /// Monotonic sequence number across all asynchronous event kinds.
    pub sequence: u64,
    /// Command active when the event arrived.
    pub command: CommandIndex,
    /// Decoded event.
    pub event: AsyncEvent,
}

#[derive(Clone, Eq, Hash, PartialEq)]
/// Backend cancellation credentials captured during startup.
pub struct CancelKey {
    /// Backend process identifier.
    pub process_id: u32,
    /// Opaque cancellation secret; its debug representation is redacted.
    pub secret_key: Bytes,
}

impl std::fmt::Debug for CancelKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CancelKey")
            .field("process_id", &self.process_id)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// A protocol-advancing message, optionally closing a command boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionItem {
    /// An ordinary protocol-advancing backend message.
    Message(BackendMessage),
    /// Readiness together with pooling-relevant state accumulated by the demux.
    ReadyForQuery {
        /// Backend transaction status.
        status: TransactionStatus,
        /// Whether run-time parameters differ from their startup baseline.
        parameters_changed: bool,
    },
    /// Command completion with notices accumulated since the previous boundary.
    CommandComplete {
        /// Backend command tag.
        tag: Bytes,
        /// Completed command's position in the session.
        command: CommandIndex,
        /// Notices attributed to this command.
        notices: Vec<TaggedNotice>,
    },
}

/// State owned below the typestate API for causally independent backend messages.
#[derive(Debug, Default)]
pub struct Demux {
    command: CommandIndex,
    pending_notices: Vec<TaggedNotice>,
    notices: VecDeque<TaggedNotice>,
    notifications: VecDeque<Notification>,
    parameter_statuses: VecDeque<ParameterStatus>,
    async_events: VecDeque<OrderedAsyncEvent>,
    next_async_sequence: u64,
    parameters: BTreeMap<Bytes, Bytes>,
    startup_parameters: Option<BTreeMap<Bytes, Bytes>>,
    parameters_changed: bool,
    cancel_key: Option<CancelKey>,
    transaction_status: Option<TransactionStatus>,
}

impl Demux {
    /// Reports whether a backend message is causally independent of session progress.
    ///
    /// Pipeline orchestration uses this shared classifier rather than defining a
    /// second asynchronous-message taxonomy.
    #[must_use]
    pub fn is_asynchronous(message: &BackendMessage) -> bool {
        matches!(
            message,
            BackendMessage::NoticeResponse(_)
                | BackendMessage::ParameterStatus { .. }
                | BackendMessage::NotificationResponse { .. }
                | BackendMessage::BackendKeyData { .. }
        )
    }

    /// Routes one decoded backend message.
    ///
    /// Async messages are consumed and recorded; only session-advancing messages
    /// are returned.
    pub fn route(&mut self, message: BackendMessage) -> Option<SessionItem> {
        match message {
            BackendMessage::NoticeResponse(fields) => {
                let notice = TaggedNotice {
                    command: self.command,
                    fields,
                };
                self.pending_notices.push(notice.clone());
                self.notices.push_back(notice.clone());
                self.push_async(AsyncEvent::Notice(notice));
                None
            }
            BackendMessage::ParameterStatus { name, value } => {
                self.parameters.insert(name.clone(), value.clone());
                let status = ParameterStatus { name, value };
                self.parameter_statuses.push_back(status.clone());
                self.push_async(AsyncEvent::ParameterStatus(status));
                if let Some(startup_parameters) = &self.startup_parameters {
                    self.parameters_changed = self.parameters != *startup_parameters;
                }
                None
            }
            BackendMessage::NotificationResponse {
                process_id,
                channel,
                payload,
            } => {
                let notification = Notification {
                    process_id,
                    channel,
                    payload,
                };
                self.notifications.push_back(notification.clone());
                self.push_async(AsyncEvent::Notification(notification));
                None
            }
            BackendMessage::BackendKeyData {
                process_id,
                secret_key,
            } => {
                self.cancel_key = Some(CancelKey {
                    process_id,
                    secret_key: secret_key.clone(),
                });
                Some(SessionItem::Message(BackendMessage::BackendKeyData {
                    process_id,
                    secret_key,
                }))
            }
            BackendMessage::ReadyForQuery(status) => {
                self.transaction_status = Some(status);
                if self.startup_parameters.is_none() {
                    self.startup_parameters = Some(self.parameters.clone());
                }
                Some(SessionItem::ReadyForQuery {
                    status,
                    parameters_changed: self.parameters_changed,
                })
            }
            BackendMessage::CommandComplete(tag) => {
                let command = self.command;
                let notices = std::mem::take(&mut self.pending_notices);
                self.command.0 = self.command.0.saturating_add(1);
                Some(SessionItem::CommandComplete {
                    tag,
                    command,
                    notices,
                })
            }
            message => Some(SessionItem::Message(message)),
        }
    }

    /// Returns the latest value of every reported run-time parameter.
    #[must_use]
    pub fn parameters(&self) -> &BTreeMap<Bytes, Bytes> {
        &self.parameters
    }

    /// Reports whether parameters differ from the startup baseline.
    #[must_use]
    pub const fn parameters_changed(&self) -> bool {
        self.parameters_changed
    }

    /// Returns the most recently received cancellation key, if any.
    #[must_use]
    pub const fn cancel_key(&self) -> Option<&CancelKey> {
        self.cancel_key.as_ref()
    }

    /// Returns the latest backend transaction status, if readiness was observed.
    #[must_use]
    pub const fn transaction_status(&self) -> Option<TransactionStatus> {
        self.transaction_status
    }

    /// Removes the next queued asynchronous notification.
    pub fn pop_notification(&mut self) -> Option<Notification> {
        self.notifications.pop_front()
    }

    /// Removes the next positionally tagged notice for prompt client forwarding.
    pub fn pop_notice(&mut self) -> Option<TaggedNotice> {
        self.notices.pop_front()
    }

    /// Removes the next ordered status update for forwarding to a client.
    pub fn pop_parameter_status(&mut self) -> Option<ParameterStatus> {
        self.parameter_statuses.pop_front()
    }

    /// Removes the next asynchronous event in original backend wire order.
    pub fn pop_async_event(&mut self) -> Option<OrderedAsyncEvent> {
        self.async_events.pop_front()
    }

    fn push_async(&mut self, event: AsyncEvent) {
        let sequence = self.next_async_sequence;
        self.next_async_sequence = self.next_async_sequence.saturating_add(1);
        self.async_events.push_back(OrderedAsyncEvent {
            sequence,
            command: self.command,
            event,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_are_attached_to_their_command_boundary() {
        let mut demux = Demux::default();
        assert_eq!(
            demux.route(BackendMessage::NoticeResponse(DiagnosticResponse {
                fields: vec![crate::codec::DiagnosticField {
                    code: b'M',
                    value: Bytes::from_static(b"notice"),
                }],
            })),
            None
        );
        let completion = demux
            .route(BackendMessage::CommandComplete(Bytes::from_static(
                b"SELECT 1",
            )))
            .expect("command completion advances the session");
        assert_eq!(
            completion,
            SessionItem::CommandComplete {
                tag: Bytes::from_static(b"SELECT 1"),
                command: CommandIndex(0),
                notices: vec![TaggedNotice {
                    command: CommandIndex(0),
                    fields: DiagnosticResponse {
                        fields: vec![crate::codec::DiagnosticField {
                            code: b'M',
                            value: Bytes::from_static(b"notice"),
                        }],
                    },
                }],
            }
        );
        assert_eq!(
            demux.pop_notice(),
            Some(TaggedNotice {
                command: CommandIndex(0),
                fields: DiagnosticResponse {
                    fields: vec![crate::codec::DiagnosticField {
                        code: b'M',
                        value: Bytes::from_static(b"notice"),
                    }],
                },
            })
        );
        assert_eq!(demux.pop_notice(), None);
    }

    #[test]
    fn startup_parameters_establish_a_clean_baseline() {
        let mut demux = Demux::default();
        assert!(
            demux
                .route(BackendMessage::ParameterStatus {
                    name: Bytes::from_static(b"client_encoding"),
                    value: Bytes::from_static(b"UTF8"),
                })
                .is_none()
        );
        demux.route(BackendMessage::ReadyForQuery(TransactionStatus::Idle));
        assert!(!demux.parameters_changed());

        demux.route(BackendMessage::ParameterStatus {
            name: Bytes::from_static(b"client_encoding"),
            value: Bytes::from_static(b"LATIN1"),
        });
        assert!(demux.parameters_changed());
    }

    #[test]
    fn parameter_statuses_remain_ordered_for_proxy_forwarding() {
        let mut demux = Demux::default();
        for (name, value) in [
            (b"TimeZone".as_slice(), b"UTC".as_slice()),
            (b"TimeZone", b"GMT"),
        ] {
            assert!(
                demux
                    .route(BackendMessage::ParameterStatus {
                        name: Bytes::copy_from_slice(name),
                        value: Bytes::copy_from_slice(value),
                    })
                    .is_none()
            );
        }

        assert_eq!(
            demux.pop_parameter_status(),
            Some(ParameterStatus {
                name: Bytes::from_static(b"TimeZone"),
                value: Bytes::from_static(b"UTC"),
            })
        );
        assert_eq!(
            demux.pop_parameter_status(),
            Some(ParameterStatus {
                name: Bytes::from_static(b"TimeZone"),
                value: Bytes::from_static(b"GMT"),
            })
        );
        assert_eq!(demux.pop_parameter_status(), None);
        assert_eq!(
            demux.parameters().get(b"TimeZone".as_slice()),
            Some(&Bytes::from_static(b"GMT"))
        );
    }

    #[test]
    fn notification_is_not_a_session_transition() {
        let mut demux = Demux::default();
        assert!(
            demux
                .route(BackendMessage::NotificationResponse {
                    process_id: 42,
                    channel: Bytes::from_static(b"events"),
                    payload: Bytes::from_static(b"payload"),
                })
                .is_none()
        );
        assert_eq!(
            demux.pop_notification(),
            Some(Notification {
                process_id: 42,
                channel: Bytes::from_static(b"events"),
                payload: Bytes::from_static(b"payload"),
            })
        );
    }

    #[test]
    fn asynchronous_events_preserve_cross_kind_wire_order() {
        let mut demux = Demux::default();
        demux.route(BackendMessage::ParameterStatus {
            name: Bytes::from_static(b"TimeZone"),
            value: Bytes::from_static(b"UTC"),
        });
        demux.route(BackendMessage::NotificationResponse {
            process_id: 7,
            channel: Bytes::from_static(b"jobs"),
            payload: Bytes::from_static(b"ready"),
        });
        demux.route(BackendMessage::NoticeResponse(DiagnosticResponse {
            fields: vec![],
        }));

        let events = std::iter::from_fn(|| demux.pop_async_event()).collect::<Vec<_>>();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 0);
        assert!(matches!(events[0].event, AsyncEvent::ParameterStatus(_)));
        assert_eq!(events[1].sequence, 1);
        assert!(matches!(events[1].event, AsyncEvent::Notification(_)));
        assert_eq!(events[2].sequence, 2);
        assert!(matches!(events[2].event, AsyncEvent::Notice(_)));
        assert!(events.iter().all(|event| event.command == CommandIndex(0)));
    }
}
