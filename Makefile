OBJECTS += \
		main.o \
		openssl_rsa.o \

TERGET = rsa_encrypt_decrypt

LIB		+= -lcrypto

CFLAG 	+= -c -fPIC -w

EXTRA_GEN_FILE += \
		decrypted_file.txt \
		encrypted_file.bin \
		private_key \
		public_key \


all: ${OBJECTS}
	g++ ${OBJECTS} -o ${TERGET} ${LIB}

%.o:%.cpp
	g++ ${CFLAG} $< -o $@ $(LIB)

clean:
	rm -rf ${OBJECTS} ${TERGET}

deep_clean:
	rm -rf ${OBJECTS} ${TERGET} ${EXTRA_GEN_FILE}
