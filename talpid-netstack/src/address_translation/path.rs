use super::*;
use crate::{
    fragment_state::FragmentState,
    packet_sizing::{self, Emission, Feedback, FeedbackQueue, FeedbackSide},
};
use std::time::Instant;

pub enum TranslationOutcome {
    Packets(Emission),
    PendingFragments,
    FeedbackQueued(FeedbackSide),
}

/// The complete production boundary: reassemble, translate, size, then retain
/// packets/feedback with this exact attempt through the consumer's final write.
pub struct TargetPacketPath {
    mapper: AddressTranslator,
    fragments: FragmentState,
    feedback: FeedbackQueue,
}

impl TargetPacketPath {
    pub fn new(
        config: TargetConfig,
        attempt: RelayAttempt,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> Result<Self, TranslationError> {
        let mapper = AddressTranslator::new(config, attempt, buffers.clone())?;
        let fragments = FragmentState::new(buffers.as_ref())?;
        let feedback = FeedbackQueue::new(buffers.as_ref())?;
        Ok(Self {
            mapper,
            fragments,
            feedback,
        })
    }
    pub fn config(&self) -> TargetConfig {
        self.mapper.config()
    }
    pub fn summary(&self) -> &TranslationSummary {
        self.mapper.summary()
    }
    pub fn backend_refused(&mut self) {
        self.mapper.backend_refused();
    }
    pub fn take_feedback(&mut self) -> Option<Feedback> {
        if !self.mapper.attempt.current() {
            self.feedback.clear();
            return None;
        }
        self.feedback.pop()
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.fragments
            .deadline()
            .into_iter()
            .chain(self.feedback.deadline())
            .min()
    }
    pub fn maintain(&mut self, now: Instant) {
        if !self.mapper.attempt.current() {
            self.fragments.clear();
            self.feedback.clear();
        } else {
            self.fragments.maintain(now);
            self.feedback.maintain(now);
        }
    }
    pub fn process(
        &mut self,
        bytes: &[u8],
        direction: Direction,
        sink_mtu: u16,
        now: Instant,
    ) -> Result<TranslationOutcome, TranslationError> {
        let mut result = self.process_inner(bytes, direction, sink_mtu, now);
        if !self.mapper.attempt.current() {
            result = Err(TranslationError::Stale);
        }
        match &result {
            Ok(TranslationOutcome::Packets(_)) => {
                self.mapper.summary.translated = self.mapper.summary.translated.saturating_add(1)
            }
            Err(reason) => self.mapper.summary.refuse(*reason),
            _ => (),
        }
        result
    }
    fn process_inner(
        &mut self,
        bytes: &[u8],
        direction: Direction,
        sink_mtu: u16,
        now: Instant,
    ) -> Result<TranslationOutcome, TranslationError> {
        self.maintain(now);
        if !self.mapper.attempt.current() {
            return Err(TranslationError::Stale);
        }
        if sink_mtu < 68 {
            return Err(TranslationError::Malformed);
        }
        let header = Header::parse_fragment(bytes)?;
        self.mapper.endpoints(&header, direction)?;
        let Some(datagram) = self.fragments.ingest(bytes, direction, now)? else {
            return Ok(TranslationOutcome::PendingFragments);
        };
        let header = self.mapper.validate_packet(&datagram.bytes, direction)?;
        let output_mtu = if direction == Direction::Outbound {
            self.mapper.config.mtu
        } else {
            sink_mtu
        };
        // Decide impossibility from the validated input before spending ordinary
        // data credit. Reserved feedback must progress when data credit is full.
        let needs_feedback = datagram.bytes.len() > usize::from(output_mtu)
            && if header.ipv4 {
                word(&datagram.bytes, 6) & 0x4000 != 0
                    || usize::from(output_mtu) < header.transport + 8
            } else {
                datagram
                    .fragmentation
                    .is_none_or(|fragment| usize::from(output_mtu) < fragment.boundary + 16)
            };
        let emitted = if needs_feedback {
            Err(TranslationError::PacketTooBig)
        } else {
            let translated = self.mapper.translate_buffer(&datagram.bytes, direction)?;
            packet_sizing::emit(
                &translated,
                output_mtu,
                datagram.fragmentation,
                &self.mapper.attempt,
                self.mapper.buffers.as_ref(),
            )
        };
        match emitted {
            Ok(packets) => Ok(TranslationOutcome::Packets(packets)),
            Err(TranslationError::PacketTooBig) => {
                let header = Header::parse(&datagram.bytes, false)?;
                let sources = if direction == Direction::Outbound {
                    self.mapper.config.fixed
                } else {
                    self.mapper.config.assigned
                };
                let source = if header.ipv4 {
                    sources.ipv4.map(IpAddr::V4)
                } else {
                    sources.ipv6.map(IpAddr::V6)
                }
                .ok_or(TranslationError::Family)?;
                let side = if direction == Direction::Outbound {
                    FeedbackSide::App
                } else {
                    FeedbackSide::Target
                };
                let return_mtu = if side == FeedbackSide::App {
                    sink_mtu
                } else {
                    self.mapper.config.mtu
                };
                self.feedback.generate(
                    &datagram.invoking,
                    &datagram.bytes,
                    packet_sizing::FeedbackRoute {
                        source,
                        mtu: output_mtu,
                        return_mtu,
                        side,
                    },
                    &self.mapper.attempt,
                    now,
                )?;
                Ok(TranslationOutcome::FeedbackQueued(side))
            }
            Err(error) => Err(error),
        }
    }
}
