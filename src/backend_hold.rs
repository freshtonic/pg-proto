use crate::codec::BackendMessage;

#[derive(Debug, Default)]
pub(crate) struct BackendHold {
    pending: Option<(BackendMessage, usize)>,
    held: Vec<BackendMessage>,
    held_bytes: usize,
}

impl BackendHold {
    pub(crate) fn set_pending(&mut self, message: BackendMessage) {
        assert!(
            self.pending.is_none(),
            "only one backend source may be pending"
        );
        let bytes = retained_bytes(&message);
        self.pending = Some((message, bytes));
    }

    pub(crate) fn pending(&self) -> Option<&BackendMessage> {
        self.pending.as_ref().map(|(message, _)| message)
    }

    pub(crate) fn take_pending(&mut self) -> Option<BackendMessage> {
        self.pending.take().map(|(message, _)| message)
    }

    pub(crate) fn hold_pending(&mut self) {
        let (message, bytes) = self.pending.take().expect("a backend source is pending");
        self.held.push(message);
        self.held_bytes = self.held_bytes.saturating_add(bytes);
    }

    pub(crate) fn messages(&self) -> &[BackendMessage] {
        &self.held
    }

    pub(crate) fn len(&self) -> usize {
        self.held.len()
    }

    pub(crate) fn bytes(&self) -> usize {
        self.held_bytes
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    pub(crate) fn clear(&mut self) -> Vec<BackendMessage> {
        self.held_bytes = 0;
        std::mem::take(&mut self.held)
    }
}

fn retained_bytes(message: &BackendMessage) -> usize {
    message
        .to_frame()
        .map_or(0, |frame| frame.body.len().saturating_add(5))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::DataRow;

    fn row(value: &'static [u8]) -> BackendMessage {
        BackendMessage::DataRow(DataRow {
            columns: vec![Some(Bytes::from_static(value))],
        })
    }

    #[test]
    fn pending_moves_into_ordered_accounted_hold() {
        let mut hold = BackendHold::default();
        hold.set_pending(row(b"one"));
        assert_eq!(hold.pending(), Some(&row(b"one")));
        hold.hold_pending();
        hold.set_pending(row(b"two"));
        hold.hold_pending();
        assert_eq!(hold.len(), 2);
        assert!(hold.bytes() > 0);
        assert_eq!(hold.clear(), vec![row(b"one"), row(b"two")]);
        assert!(hold.is_empty());
        assert_eq!(hold.bytes(), 0);
    }
}
