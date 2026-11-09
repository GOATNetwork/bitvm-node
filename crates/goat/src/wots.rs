use bitcoin::script::read_scriptint;
use bitcoin::Witness;
use bitvm::signatures::utils::bitcoin_representation;
pub use bitvm::signatures::winternitz::{Parameters, VoidConverter};
pub use bitvm::signatures::{
    CompactWots, GenericWinternitzPublicKey, WinternitzSecret, WinternitzSigningInputs, Wots,
    Wots16, Wots32, Wots4, Wots64, Wots80,
};

pub const WOTS96_LOG2_BASE: u32 = 8;
pub const WOTS96_BASE: u32 = 1 << WOTS96_LOG2_BASE;

pub struct Wots96;

impl Wots for Wots96 {
    type Converter = VoidConverter;
    type PublicKey = [[u8; 20]; Self::TOTAL_DIGIT_LEN as usize];
    type Message = [u8; Self::MSG_BYTE_LEN as usize];
    type Signature = [[u8; 21]; Self::TOTAL_DIGIT_LEN as usize];

    const MSG_BYTE_LEN: u32 = 96;
    const PARAMETERS: Parameters =
        Parameters::new_by_bit_length(Self::MSG_BYTE_LEN * 8, WOTS96_LOG2_BASE);

    fn raw_witness_to_signature(witness: &Witness) -> Self::Signature {
        assert_eq!(witness.len(), 2 * Self::TOTAL_DIGIT_LEN as usize);

        let mut digit_signatures = Vec::with_capacity(Self::TOTAL_DIGIT_LEN as usize);
        for i in (0..witness.len()).step_by(2) {
            assert_eq!(
                witness[i].len(),
                20,
                "the digit signature should be constant 20 bytes"
            );
            assert!(
                witness[i + 1].len() <= 2,
                "the base256 digit should fit in minimally encoded script bytes"
            );

            let digit_value = read_scriptint(&witness[i + 1]).unwrap();
            assert!(
                (0..WOTS96_BASE as i64).contains(&digit_value),
                "the digit should be in the valid Wots96 base range"
            );

            let mut digit_signature = [0u8; 21];
            digit_signature[..20].copy_from_slice(&witness[i]);
            digit_signature[20] = digit_value as u8;
            digit_signatures.push(digit_signature);
        }

        Self::Signature::try_from(digit_signatures).unwrap()
    }

    fn signature_to_raw_witness(signature: &Self::Signature) -> Witness {
        let mut witness = Witness::new();

        for digit_signature in signature.as_ref() {
            witness.push(&digit_signature[..20]);
            witness.push(bitcoin_representation(i32::from(digit_signature[20])));
        }

        witness
    }

    fn signature_to_message(signature: &Self::Signature) -> Self::Message {
        if WOTS96_LOG2_BASE == 8 {
            let bytes = signature
                .as_ref()
                .iter()
                .map(|digit_sig| digit_sig[20])
                .take(Self::MSG_BYTE_LEN as usize)
                .rev()
                .collect::<Vec<_>>();

            return Self::Message::try_from(bytes).unwrap();
        }

        let digits = signature
            .as_ref()
            .iter()
            .map(|digit_sig| digit_sig[20])
            .take(((Self::MSG_BYTE_LEN * 8).div_ceil(WOTS96_LOG2_BASE)) as usize)
            .rev()
            .collect::<Vec<_>>();

        let mut bytes = Vec::with_capacity(Self::MSG_BYTE_LEN as usize);
        let mut byte = 0u8;
        let mut used_bits = 0u32;
        for digit in digits {
            byte |= digit << used_bits;
            used_bits += WOTS96_LOG2_BASE;
            if used_bits >= 8 {
                bytes.push(byte);
                byte = digit >> (8 - (used_bits - WOTS96_LOG2_BASE));
                used_bits -= 8;
            }
        }
        bytes.truncate(Self::MSG_BYTE_LEN as usize);

        Self::Message::try_from(bytes).unwrap()
    }
}

impl CompactWots for Wots96 {
    type CompactSignature = [[u8; 20]; Self::TOTAL_DIGIT_LEN as usize];
}

pub type Wots96Secret = WinternitzSecret;
