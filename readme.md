`keytool -genseckey -alias key -keysize 128 -keyalg AES -storepass "securepass123" -storetype JCEKS -keystore .keystore`

keystore has two keys: 
`key`,
`key2`

`./enctool.py -i key -g -p securepass123  -m ICBC -k .keystore`