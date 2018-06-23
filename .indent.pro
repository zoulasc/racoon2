/* $Id: .indent.pro,v 1.2 2005/10/06 10:56:02 inoue Exp $ */

-brs -hnl -bbo -nbad -nbap -nbbb -ncs -nbc -br -c33 -cd33 -ncdb -ce -ci8
-cli0 -d0 -di0 -ndj -nfc1 -i8 -ip8 -l80 -lp -npcs -psl -sc -ss -sob -ts8

-T int -T char -T u_char -T u_short -T u_int -T u_long -T u_int8_t
-T u_int16_t -T u_int32_t -T caddr_t -T size_t -T fd_set

-T vchar_t -T rcf_t -T rcf_tdir -T rc_type

-T EVP_MD_CTX -T HMAC_CTX -T X509_STORE_CTX -T EVP_CIPHER_CTX -T CBCMAC_CTX
-T SHA512_CTX -T SHA384_CTX -T SHA256_CTX

-T PH1EXCHG -T PH2EXCHG -T IKEV2INPUT -T isakmp_cookie_t -T msgid_t
-T isakmp_index_t -T cert_t
