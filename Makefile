#export PATH=/home/john/proj/mxe/usr/bin:$PATH
#export PATH=/home/peka/src/mxe/usr/bin:$PATH
#CROSS=i686-w64-mingw32.static-
#CROSS_EXT=.exe
CROSS=
CC=$(CROSS)gcc
AR=$(CROSS)ar
LDFLAGS=-lgcrypt -lgpg-error
GDBFLAGS=-g -Wall

ZIP_FILE_PATH=cr_app.zip

SRC_PATH=src
DEST_PATH=dest
DATA_PATH=data

SRC_CR_PATH=$(SRC_PATH)/cr
SRC_CR_ENCRYPT_PATH=$(SRC_PATH)/cr_encrypt
SRC_CR_DECRYPT_PATH=$(SRC_PATH)/cr_decrypt
SRC_CR_SERVER_PATH=$(SRC_PATH)/cr_server
SRC_CR_KEYGEN_PATH=$(SRC_PATH)/cr_keygen

DEST_CR_PATH=$(DEST_PATH)/cr
DEST_CR_ENCRYPT_PATH=$(DEST_PATH)/cr_encrypt
DEST_CR_DECRYPT_PATH=$(DEST_PATH)/cr_decrypt
DEST_CR_SERVER_PATH=$(DEST_PATH)/cr_server
DEST_CR_KEYGEN_PATH=$(DEST_PATH)/cr_keygen
DEST_CR_DATA_PATH=$(DEST_PATH)/cr_data

DATA_KEYS_PATH=$(DATA_PATH)/keys
DATA_KEYS_CR_PATH=$(DATA_KEYS_PATH)/cr

all: dest cr_encrypt cr_keygen

dest: clean_dest
	mkdir $(DEST_PATH)
	mkdir $(DEST_CR_PATH)
	mkdir $(DEST_CR_ENCRYPT_PATH)
	mkdir $(DEST_CR_DECRYPT_PATH)
	mkdir $(DEST_CR_SERVER_PATH)
	mkdir $(DEST_CR_KEYGEN_PATH)
	mkdir $(DEST_CR_DATA_PATH)
	
cr_encrypt: cr_encrypt_lib
	$(CC) -static $(SRC_CR_ENCRYPT_PATH)/main.c \
	-L$(DEST_CR_ENCRYPT_PATH)/ -lcr_encrypt $(LDFLAGS) $(GDBFLAGS) \
	-o $(DEST_CR_ENCRYPT_PATH)/cr_encrypt$(CROSS_EXT)

cr_encrypt_lib: cr data_keys_cr_binary 
	cp $(DEST_CR_PATH)/libcr.a $(DEST_CR_ENCRYPT_PATH)/libcr_encrypt.a
	$(CC) -c $(SRC_CR_ENCRYPT_PATH)/app.c -o $(DEST_CR_ENCRYPT_PATH)/app.o $(GDBFLAGS)
	$(AR) rcs $(DEST_CR_ENCRYPT_PATH)/libcr_encrypt.a \
	$(DEST_CR_DATA_PATH)/keys_cr_keyp.o \
	$(DEST_CR_ENCRYPT_PATH)/app.o

cr_keygen: cr 
	$(CC) -static $(SRC_CR_KEYGEN_PATH)/main.c \
	-L$(DEST_CR_PATH)/ -lcr $(LDFLAGS) $(GDBFLAGS) \
	-o $(DEST_CR_KEYGEN_PATH)/cr_keygen$(CROSS_EXT)
cr:
	$(CC) -c $(SRC_CR_PATH)/base64.c     -o $(DEST_CR_PATH)/base64.o     $(GDBFLAGS)
	$(CC) -c $(SRC_CR_PATH)/directory.c -o $(DEST_CR_PATH)/directory.o $(GDBFLAGS)
	$(CC) -c $(SRC_CR_PATH)/file.c      -o $(DEST_CR_PATH)/file.o      $(GDBFLAGS)
	$(CC) -c $(SRC_CR_PATH)/aes.c       -o $(DEST_CR_PATH)/aes.o       $(GDBFLAGS)
	$(CC) -c $(SRC_CR_PATH)/rsa.c       -o $(DEST_CR_PATH)/rsa.o       $(GDBFLAGS)
	$(CC) -c $(SRC_CR_PATH)/hash.c      -o $(DEST_CR_PATH)/hash.o      $(GDBFLAGS)
	$(CC) -c $(SRC_CR_PATH)/random.c    -o $(DEST_CR_PATH)/random.o    $(GDBFLAGS)
	$(CC) -c $(SRC_CR_PATH)/crypt.c     -o $(DEST_CR_PATH)/crypt.o     $(GDBFLAGS)
	$(AR) rcs $(DEST_CR_PATH)/libcr.a \
	$(DEST_CR_PATH)/base64.o \
	$(DEST_CR_PATH)/directory.o \
	$(DEST_CR_PATH)/file.o \
	$(DEST_CR_PATH)/aes.o \
	$(DEST_CR_PATH)/rsa.o \
	$(DEST_CR_PATH)/hash.o \
	$(DEST_CR_PATH)/random.o \
	$(DEST_CR_PATH)/crypt.o

data_keys_cr_binary:
	ld -r -b binary -o $(DEST_CR_DATA_PATH)/keys_cr_keyp.o $(DATA_KEYS_CR_PATH)/keyp

zip: clean_zip
	zip -r $(ZIP_FILE_PATH) .

clean: clean_dest clean_zip
	rm -f *\~

clean_zip:
	rm -f $(ZIP_FILE_PATH)

clean_dest:
	rm -rf $(DEST_PATH)
