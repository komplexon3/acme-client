package acme_errors

const (
	ACCOUNTDOESNOTEXIST     = "urn:ietf:params:acme:error:t"
	ALREADYREVOKED          = "urn:ietf:params:acme:error:alreadyRevoked"
	BADCSR                  = "urn:ietf:params:acme:error:badCSR"
	BADNONCE                = "urn:ietf:params:acme:error:badNonce"
	BADPUBLICKEY            = "urn:ietf:params:acme:error:badPublicKey"
	BADREVOCATIONREASON     = "urn:ietf:params:acme:error:badRevocationReason"
	BADSIGNATUREALGORITHM   = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	CAA                     = "urn:ietf:params:acme:error:caa"
	COMPOUND                = "urn:ietf:params:acme:error:compound"
	CONNECTION              = "urn:ietf:params:acme:error:connection"
	DNS                     = "urn:ietf:params:acme:error:dns"
	EXTERNALACCOUNTREQUIRED = "urn:ietf:params:acme:error:externalAccountRequired"
	INCORRECTRESPONSE       = "urn:ietf:params:acme:error:incorrectResponse"
	INVALIDCONTACT          = "urn:ietf:params:acme:error:invalidContact"
	MALFORMED               = "urn:ietf:params:acme:error:malformed"
	ORDERNOTREADY           = "urn:ietf:params:acme:error:orderNotReady"
	RATELIMITED             = "urn:ietf:params:acme:error:rateLimited"
	REJECTEDIDENTIFIER      = "urn:ietf:params:acme:error:rejectedIdentifier"
	SERVERINTERNAL          = "urn:ietf:params:acme:error:serverInternal"
	TLS                     = "urn:ietf:params:acme:error:tls"
	UNAUTHORIZED            = "urn:ietf:params:acme:error:d"
	UNSUPPORTEDCONTACT      = "urn:ietf:params:acme:error:unsupportedContact"
	UNSUPPORTEDIDENTIFIER   = "urn:ietf:params:acme:error:unsupportedIdentifier"
	USERACTIONREQUIRED      = "urn:ietf:params:acme:error:userActionRequired"
)

func GetErrorDetails(err string) string {
	switch err {
	case ACCOUNTDOESNOTEXIST:
		return "The request specified an account that does not exist"
	case ALREADYREVOKED:
		return "The request specified a certificate to be revoked that has already been revoked"
	case BADCSR:
		return "The CSR is unacceptable (e.g., due to a short key)"
	case BADNONCE:
		return "The client sent an unacceptable anti-replay nonce"
	case BADPUBLICKEY:
		return "The JWS was signed by a public key th server does not support"
	case BADREVOCATIONREASON:
		return "The revocation reason provided is not allowed by the server"
	case BADSIGNATUREALGORITHM:
		return "The JWS was signed with an algorithm the server does not support"
	case CAA:
		return "Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate"
	case COMPOUND:
		return "Specific error conditions are indicated in the `subproblems` array"
	case CONNECTION:
		return "The server could not connect to validation target"
	case DNS:
		return "There was a problem with a DNS query during identifier validation"
	case EXTERNALACCOUNTREQUIRED:
		return "The request must include a value for the 'externalAccountBinding' field"
	case INCORRECTRESPONSE:
		return "Response received didn't match the challenge's requirements"
	case INCORRECTRESPONSE:
		return "A contact URL for an account was invalid"
	case MALFORMED:
		return "The request message was malformed"
	case ORDERNOTREADY:
		return "The request attempted to finalize an order that is not ready to be finalized"
	case RATELIMITED:
		return "The request exceeds a rate limit"
	case REJECTEDIDENTIFIER:
		return "The server will not issue certificates for the identifier"
	case SERVERINTERNAL:
		return "The server experienced an internal error"
	case TLS:
		return "The server received a TLS error during validation"
	case UNAUTHORIZED:
		return "The client lacks sufficient authorization"
	case UNSUPPORTEDCONTACT:
		return "A contact URL for an account used an unsupported protocol scheme"
	case UNSUPPORTEDIDENTIFIER:
		return "An identifier is of an unsupported type"
	case USERACTIONREQUIRED:
		return "Visit the 'instance' URL and take actions specified there"
	default:
		return "Unknown error"
	}
}
