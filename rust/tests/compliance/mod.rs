// Compliance testing module
// This module doesn't contain actual tests, but ensures that
// the code is properly annotated for Duvet compliance reporting

// Duvet annotations are added directly to the source code
// Example annotation:
//
// //= https://tools.ietf.org/html/rfc8446#section-4.1.2
// //# struct {
// //#   ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
// //#   Random random;
// //#   opaque legacy_session_id<0..32>;
// //#   CipherSuite cipher_suites<2..2^16-2>;
// //#   opaque legacy_compression_methods<1..2^8-1>;
// //#   Extension extensions<8..2^16-1>;
// //# } ClientHello;
// fn parse_client_hello(buf: &[u8]) -> Result<ClientHello, Error> {
//     // Implementation
// }
//
// The compliance report is generated using the duvet tool:
// $ duvet report