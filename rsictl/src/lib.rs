mod api;
mod ioctl;
mod token;
// the below can be removed at some point, debug purposes only
mod token_c;

// dev handlers
pub use api::dev_read;
pub use api::dev_write;

// ioctls
pub use api::abi_version;
pub use api::attestation_token;
pub use api::measurement_extend;
pub use api::measurement_read;

// token
pub use token::TokenError;
pub use token::verifier::verify_token;
pub use token::dumper::print_token;

// token_c
pub use token_c::TokenError as CTokenError;
pub use token_c::verify_token as c_verify_token;
pub use token_c::print_raw_token as c_print_raw_token;
pub use token_c::print_token as c_print_token;
pub use token_c::print_token_rust as c_print_token_rust;
