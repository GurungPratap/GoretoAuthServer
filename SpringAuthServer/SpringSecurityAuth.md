keytool -genkeypair -alias springsecauth -keyalg RSA -keysize 2048 -validity 3650 -keystore springsecauth.jks -storepass springsecauth -keypass springsecauth


# Export cert from JKS
keytool -exportcert -alias springsecauth -keystore springsecauth.jks -rfc -storepass springsecauth -file public.crt

# Extract PKCS#8 public key from cert
openssl x509 -in public.crt -pubkey -noout > public.key
