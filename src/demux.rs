//! Filtering projection from backend messages to the typed session stream.

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use crate::codec::{BackendMessage, DiagnosticResponse, TransactionStatus};

/// Position of a command within a connection's session.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct CommandIndex(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaggedNotice {
    pub command: CommandIndex,
    pub fields: DiagnosticResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Notification {
    pub process_id: u32,
    pub channel: Bytes,
    pub payload: Bytes,
}

/// One ordered `ParameterStatus` update retained for proxy forwarding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterStatus {
    pub name: Bytes,
    pub value: Bytes,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CancelKey {
    pub process_id: u32,
    pub secret_key: Bytes,
}

/// A protocol-advancing message, optionally closing a command boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionItem {
    Message(BackendMessage),
    ReadyForQuery {
        status: TransactionStatus,
        parameters_changed: bool,
    },
    CommandComplete {
        tag: Bytes,
        command: CommandIndex,
        notices: Vec<TaggedNotice>,
    },
}

/// State owned below the typestate API for causally independent backend messages.
#[derive(Debug, Default)]
pub struct Demux {
    command: CommandIndex,
    pending_notices: Vec<TaggedNotice>,
    notifications: VecDeque<Notification>,
    parameter_statuses: VecDeque<ParameterStatus>,
    parameters: BTreeMap<Bytes, Bytes>,
    startup_parameters: Option<BTreeMap<Bytes, Bytes>>,
    parameters_changed: bool,
    cancel_key: Option<CancelKey>,
    transaction_status: Option<TransactionStatus>,
}

impl Demux {
    /// Routes one decoded backend message.
    ///
    /// Async messages are consumed and recorded; only session-advancing messages
    /// are returned.
    pub fn route(&mut self, message: BackendMessage) -> Option<SessionItem> {
        match message {
            BackendMessage::NoticeResponse(fields) => {
                self.pending_notices.push(TaggedNotice {
                    command: self.command,
                    fields,
                });
                None
            }
            BackendMessage::ParameterStatus { name, value } => {
                self.parameters.insert(name.clone(), value.clone());
                self.parameter_statuses
                    .push_back(ParameterStatus { name, value });
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
                self.notifications.push_back(Notification {
                    process_id,
                    channel,
                    payload,
                });
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

    #[must_use]
    pub fn parameters(&self) -> &BTreeMap<Bytes, Bytes> {
        &self.parameters
    }

    #[must_use]
    pub const fn parameters_changed(&self) -> bool {
        self.parameters_changed
    }

    #[must_use]
    pub const fn cancel_key(&self) -> Option<&CancelKey> {
        self.cancel_key.as_ref()
    }

    #[must_use]
    pub const fn transaction_status(&self) -> Option<TransactionStatus> {
        self.transaction_status
    }

    pub fn pop_notification(&mut self) -> Option<Notification> {
        self.notifications.pop_front()
    }

    /// Removes the next ordered status update for forwarding to a client.
    pub fn pop_parameter_status(&mut self) -> Option<ParameterStatus> {
        self.parameter_statuses.pop_front()
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
}
