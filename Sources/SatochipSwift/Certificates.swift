//
//  Certificates.swift
//  
//
//  Created by Satochip on 06/02/2023.
//

import Foundation

// Certificates used to authenticates genuine Satochip, Satodime & SeedKeeper.
public struct PkiCertificates {
    
    // warning: the last '\n' is required for correct parsing of PEM string
    public static let rootCAPem = """
-----BEGIN CERTIFICATE-----
MIICLTCCAbOgAwIBAgIBATAKBggqhkjOPQQDBDBeMQswCQYDVQQGEwJCRTERMA8G
A1UECAwIQnJ1c3NlbHMxEDAOBgNVBAoMB1RvcG9yaW4xKjAoBgNVBAMMIVRvcG9y
aW4gUGVyc29uYWxpemF0aW9uIFJvb3QgQ0EgMTAeFw0yMDEyMDExMjAwMDBaFw00
MDEyMDExMjAwMDBaMF4xCzAJBgNVBAYTAkJFMREwDwYDVQQIDAhCcnVzc2VsczEQ
MA4GA1UECgwHVG9wb3JpbjEqMCgGA1UEAwwhVG9wb3JpbiBQZXJzb25hbGl6YXRp
b24gUm9vdCBDQSAxMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE5ZPgeQ54Y5NdTJM4
uYU0f+vDK/D5XI9pY69i+EkgK4l++zKjsGMYY7gkEFzcqB1nQRn8ozss/0vYaMpk
oePYNqVd0ZQxwFcb/NLDyZQq3NzfTAmQjw6KMSvPL57R24K1o0UwQzASBgNVHRMB
Af8ECDAGAQH/AgEBMB0GA1UdDgQWBBRda9Hdoqr5lHwykRLBgkIVnUT6ITAOBgNV
HQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwQDaAAwZQIxAJTGtuRR9ceNqAXu5sAOp6yJ
RLdnio7RVMmIZWLishPolJFN9vPt7FSBDgxRnqUJVwIwXJNx20XtJJl6NwKLfMIK
nf1pE1NCQErS3wK9lLPZkr7uK/TpulrKJ+hc+1w7+UeU
-----END CERTIFICATE-----

"""
    
    // warning: the last '\n' is required for correct parsing of PEM string
    public static let satodimeCertPem =
"""
-----BEGIN CERTIFICATE-----
MIICHzCCAaWgAwIBAgIBBDAKBggqhkjOPQQDBDBeMQswCQYDVQQGEwJCRTERMA8G
A1UECAwIQnJ1c3NlbHMxEDAOBgNVBAoMB1RvcG9yaW4xKjAoBgNVBAMMIVRvcG9y
aW4gUGVyc29uYWxpemF0aW9uIFJvb3QgQ0EgMTAeFw0yMDEyMDExMjAwMDBaFw00
MDEyMDExMjAwMDBaMHAxCzAJBgNVBAYTAkJFMREwDwYDVQQIDAhCcnVzc2VsczEQ
MA4GA1UECgwHVG9wb3JpbjERMA8GA1UECwwIU2F0b0RpbWUxKTAnBgNVBAMMIFNh
dG9EaW1lIFBlcnNvbmFsaXphdGlvbiBTdWJDQSAxMFYwEAYHKoZIzj0CAQYFK4EE
AAoDQgAENYAbNcXAD9+vipyDH9mP2hY8N+gJIesSLztiVIWZEDS+NZ/vZmPlawb9
c/XA83JYycOcgtMSw0RGdrLTz+y9WqNFMEMwEgYDVR0TAQH/BAgwBgEB/wIBADAd
BgNVHQ4EFgQUOOdfhDL1plm+m05bAcWkzxxQbRowDgYDVR0PAQH/BAQDAgEGMAoG
CCqGSM49BAMEA2gAMGUCMCGdDBkCiGukho1L7ammsegN2HytlLWH+jKFKJgoMKrf
jK5xFepoyKpUecE8zYKP/wIxANIfiuRCe85Lk/QQH3TCRjwIl4582Y9xwbkxwA7X
qMwFBMHquXkHmG/XWA4Q/gx6mg==
-----END CERTIFICATE-----

"""

    // warning: the last '\n' is required for correct parsing of PEM string
    public static let satochipCertPem =
"""
-----BEGIN CERTIFICATE-----
MIICIDCCAaWgAwIBAgIBAzAKBggqhkjOPQQDBDBeMQswCQYDVQQGEwJCRTERMA8G
A1UECAwIQnJ1c3NlbHMxEDAOBgNVBAoMB1RvcG9yaW4xKjAoBgNVBAMMIVRvcG9y
aW4gUGVyc29uYWxpemF0aW9uIFJvb3QgQ0EgMTAeFw0yMDEyMDExMjAwMDBaFw00
MDEyMDExMjAwMDBaMHAxCzAJBgNVBAYTAkJFMREwDwYDVQQIDAhCcnVzc2VsczEQ
MA4GA1UECgwHVG9wb3JpbjERMA8GA1UECwwIU2F0b2NoaXAxKTAnBgNVBAMMIFNh
dG9jaGlwIFBlcnNvbmFsaXphdGlvbiBTdWJDQSAxMFYwEAYHKoZIzj0CAQYFK4EE
AAoDQgAEcTVxDGkXKyV0kaRXu+9gTrg654Xam6ktgDA/n+28+egjMmZDWroaha/6
+MPP/XBGeFAecmO0hppkgnUcwjRcw6NFMEMwEgYDVR0TAQH/BAgwBgEB/wIBADAd
BgNVHQ4EFgQUx9Plfp8o9ZCoticLc5x7CnSBriUwDgYDVR0PAQH/BAQDAgEGMAoG
CCqGSM49BAMEA2kAMGYCMQCmoDTdSMMSMogCm4l130drFFxC0wmbZwWE+xGjZIKL
9tXosnIzUx5VUqbeNXbvJBUCMQDVVRt4c4veIxdwWOv2DhJ9Ri/3it8R0v/eQ/jU
ppK2S2/ObbWSt5aAGi4EfpGZ93E=
-----END CERTIFICATE-----

"""
    
    // warning: the last '\n' is required for correct parsing of PEM string
    public static let seedkeeperCertPem =
"""
-----BEGIN CERTIFICATE-----
MIICJDCCAamgAwIBAgIBAjAKBggqhkjOPQQDBDBeMQswCQYDVQQGEwJCRTERMA8G
A1UECAwIQnJ1c3NlbHMxEDAOBgNVBAoMB1RvcG9yaW4xKjAoBgNVBAMMIVRvcG9y
aW4gUGVyc29uYWxpemF0aW9uIFJvb3QgQ0EgMTAeFw0yMDEyMDExMjAwMDBaFw00
MDEyMDExMjAwMDBaMHQxCzAJBgNVBAYTAkJFMREwDwYDVQQIDAhCcnVzc2VsczEQ
MA4GA1UECgwHVG9wb3JpbjETMBEGA1UECwwKU2VlZEtlZXBlcjErMCkGA1UEAwwi
U2VlZEtlZXBlciBQZXJzb25hbGl6YXRpb24gU3ViQ0EgMTBWMBAGByqGSM49AgEG
BSuBBAAKA0IABJpfxPfpvKohVS3Maa8nEaNOG35er0QWEhLLszdY4se11i3Rgz5Y
hKx0Ivi1NW8RBTpzYfg3sQ6y63GiExq8+sWjRTBDMBIGA1UdEwEB/wQIMAYBAf8C
AQAwHQYDVR0OBBYEFJwHa+Q9h4wdQdjfRbLPDSBwrvaXMA4GA1UdDwEB/wQEAwIB
BjAKBggqhkjOPQQDBANpADBmAjEAj667wNmFONsuz8hbw8fjVE6bzxQcUV40P91K
fsih2woWJ7UNQx4WKfgYvBiHW2ffAjEA1w47b+1Gl6LgNr6u0titPL2W02HQH0/7
1c3e4CDneXvCTfG16JJRxtMmvv+RdTsg
-----END CERTIFICATE-----

"""
    
}
