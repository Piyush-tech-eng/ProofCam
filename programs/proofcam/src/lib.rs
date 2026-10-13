use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWxqSWYBb7C5aMFgAq2j3vka1E8");

pub const MAX_CID_BYTES: usize = 64;
pub const MAX_GEOHASH_BYTES: usize = 12;
pub const SCHEMA_VERSION: u8 = 1;

#[program]
pub mod proofcam {
    use super::*;

    /// Creates one immutable record for a capture. Reusing the capture ID fails
    /// because the PDA is initialized exactly once.
    pub fn register_capture(
        ctx: Context<RegisterCapture>,
        capture_id: [u8; 32],
        image_hash: [u8; 32],
        manifest_hash: [u8; 32],
        manifest_cid: String,
        location_geohash: Option<String>,
        schema_version: u8,
    ) -> Result<()> {
        require!(capture_id != [0; 32], RegistryError::InvalidCaptureId);
        require!(image_hash != [0; 32], RegistryError::InvalidImageHash);
        require!(manifest_hash != [0; 32], RegistryError::InvalidManifestHash);
        require!(is_supported_cid(&manifest_cid), RegistryError::InvalidCid);
        require!(
            schema_version == SCHEMA_VERSION,
            RegistryError::UnsupportedSchemaVersion
        );

        if let Some(ref geohash) = location_geohash {
            require!(!geohash.is_empty(), RegistryError::InvalidGeohash);
            require!(
                geohash.as_bytes().len() <= MAX_GEOHASH_BYTES,
                RegistryError::GeohashTooLong
            );
            require!(
                geohash
                    .bytes()
                    .all(|ch| b"0123456789bcdefghjkmnpqrstuvwxyz".contains(&ch)),
                RegistryError::InvalidGeohash
            );
        }

        let record = &mut ctx.accounts.capture_record;
        record.capture_id = capture_id;
        record.image_hash = image_hash;
        record.manifest_hash = manifest_hash;
        record.authority = ctx.accounts.authority.key();
        record.registered_at = Clock::get()?.unix_timestamp;
        record.manifest_cid = manifest_cid;
        record.location_geohash = location_geohash;
        record.schema_version = schema_version;
        record.bump = ctx.bumps.capture_record;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(capture_id: [u8; 32])]
pub struct RegisterCapture<'info> {
    #[account(
        init,
        payer = authority,
        space = CaptureRecord::SPACE,
        seeds = [b"capture", capture_id.as_ref()],
        bump
    )]
    pub capture_record: Account<'info, CaptureRecord>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct CaptureRecord {
    pub capture_id: [u8; 32],
    pub image_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub authority: Pubkey,
    pub registered_at: i64,
    #[max_len(64)]
    pub manifest_cid: String,
    #[max_len(12)]
    pub location_geohash: Option<String>,
    pub schema_version: u8,
    pub bump: u8,
}

impl CaptureRecord {
    pub const SPACE: usize = 8 + Self::INIT_SPACE;
}

fn is_supported_cid(cid: &str) -> bool {
    let bytes = cid.as_bytes();
    if bytes.len() > MAX_CID_BYTES || bytes.is_empty() {
        return false;
    }
    // IPFS CIDv0 uses the base58btc multihash prefix Qm; CIDv1 base32 starts
    // with lowercase b and uses the RFC 4648 base32 alphabet without padding.
    if cid.starts_with("Qm") {
        return bytes.len() == 46
            && bytes.iter().all(|ch| {
                b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(ch)
            });
    }
    if cid.starts_with('b') {
        return bytes.len() >= 10
            && bytes
                .iter()
                .all(|ch| b"abcdefghijklmnopqrstuvwxyz234567".contains(ch));
    }
    false
}

#[error_code]
pub enum RegistryError {
    #[msg("Capture ID must not be all zeroes.")]
    InvalidCaptureId,
    #[msg("Image SHA-256 must not be all zeroes.")]
    InvalidImageHash,
    #[msg("Manifest SHA-256 must not be all zeroes.")]
    InvalidManifestHash,
    #[msg("Manifest CID is empty or malformed.")]
    InvalidCid,
    #[msg("Manifest CID exceeds the maximum byte length.")]
    CidTooLong,
    #[msg("Location geohash is invalid.")]
    InvalidGeohash,
    #[msg("Location geohash exceeds the maximum byte length.")]
    GeohashTooLong,
    #[msg("Capture schema version is not supported.")]
    UnsupportedSchemaVersion,
}
