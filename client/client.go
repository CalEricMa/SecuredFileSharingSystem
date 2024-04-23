package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	FileMap  map[string]uuid.UUID
	FileSalt map[string][]byte
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// NOTE: The following methods have toy (insecure!) implementations.

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	uuidgen, _ := uuid.FromBytes(userlib.Hash([]byte(username)))
	SourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16) //source key
	encKey, _ := userlib.HashKDF(SourceKey, []byte("encryption"))
	macKey, err := userlib.HashKDF(SourceKey, []byte("mac"))
	EncThenMac, ok := userlib.DatastoreGet(uuidgen)
	if !ok {
		return nil, err
	} //UUID doesn't exist, raise error

	Hmac_tag, err := userlib.HMACEval(macKey[:16], EncThenMac[64:])
	if !userlib.HMACEqual(EncThenMac[:64], Hmac_tag) {
		return nil, err
	} //tag not same

	ByteUser := userlib.SymDec(encKey[:16], EncThenMac[64:])
	err = json.Unmarshal(ByteUser, userdataptr)
	return userdataptr, err
}

type File struct {
	ID       uuid.UUID
	Next     uuid.UUID
	Last     uuid.UUID
	UserTree uuid.UUID
	Content  uuid.UUID
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	//Initializing the File Struct
	var file File
	file.ID = storageKey
	file.Next = uuid.Nil
	file.Last = storageKey
	file.Content = uuid.New()
	file.UserTree = uuid.New()
	//Generating the Encryption and Mac Key
	salt := userlib.RandomBytes(16)
	SourceKey := userlib.Argon2Key(userlib.Hash(storageKey[:])[:16], salt, 16) //source key
	encKey, err := userlib.HashKDF(SourceKey, []byte("encryption"))
	if err != nil {
		return err
	}
	macKey, err := userlib.HashKDF(SourceKey, []byte("mac"))
	if err != nil {
		return err
	}
	//Storing the New File Content
	err = StoreContentToDatastore(file.Content, content, encKey[:16], macKey[:16])
	if err != nil {
		return err
	}

	//Storing the New File Struct
	err = StoreFileToDatastore(storageKey, file, encKey[:16], macKey[:16])
	if err != nil {
		return err
	}
	//Storing the UserTree
	//TODO: Implement User Tree

	//Storing Information to User Struct
	//TODO: Implement Locker Room
	userdata.FileMap[filename] = storageKey
	userdata.FileSalt[filename] = salt
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	SourceKey := userlib.Argon2Key(userlib.Hash(storageKey[:])[:16], userdata.FileSalt[filename], 16) //source key
	encKey, _ := userlib.HashKDF(SourceKey, []byte("encryption"))
	macKey, _ := userlib.HashKDF(SourceKey, []byte("mac"))
	//Getting the Original File Struct
	Verified := CheckMac(storageKey, macKey[:16])
	if !Verified {
		return err
	}

	var file File
	// err = json.Unmarshal(fileJson, &file)
	file, err = DecryptFile(storageKey, encKey[:16], file)
	if err != nil {
		return errors.ErrUnsupported
	}

	//Creating a new File Struct and Temporary File Struct
	var newFile File
	var tempFile File
	newFileUUID := uuid.New()
	if storageKey == file.Last {
		file.Next = newFileUUID
		file.Last = newFileUUID
		//Storing the first File Struct
		err = StoreFileToDatastore(storageKey, file, encKey[:16], macKey[:16])
		if err != nil {
			return err
		}
	} else {
		Verified := CheckMac(file.Last, macKey[:16])
		if !Verified {
			return err
		}
		tempFile, err = DecryptFile(file.Last, encKey[:16], tempFile)
		if err != nil {
			return err
		}
		tempFile.Next = newFileUUID
		tempFile.Last = newFileUUID
		//Storing Back the File Struct
		err = StoreFileToDatastore(tempFile.ID, tempFile, encKey[:16], macKey[:16])
		if err != nil {
			return err
		}
		file.Last = newFileUUID
		//Storing the first File Struct
		err = StoreFileToDatastore(storageKey, file, encKey[:16], macKey[:16])
		if err != nil {
			return err
		}
	}
	//Creating the New File Struct
	newFile.ID = newFileUUID
	newFile.Next = uuid.Nil
	newFile.Last = newFileUUID
	newFile.Content = uuid.New()
	newFile.UserTree = uuid.New()

	//Storing the New File Content
	err = StoreContentToDatastore(newFile.Content, content, encKey[:16], macKey[:16])
	if err != nil {
		return err
	}

	//Storing the New File Struct
	err = StoreFileToDatastore(newFileUUID, newFile, encKey[:16], macKey[:16])
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//Gettg the Storage Key
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}

	//Getting the encryption and mac key
	SourceKey := userlib.Argon2Key(userlib.Hash(storageKey[:])[:16], userdata.FileSalt[filename], 16) //source key
	encKey, _ := userlib.HashKDF(SourceKey, []byte("encryption"))
	macKey, _ := userlib.HashKDF(SourceKey, []byte("mac"))

	//Getting the File Struct
	var file File
	Verified := CheckMac(storageKey, macKey[:16])
	if !Verified {
		return nil, err
	}
	file, err = DecryptFile(storageKey, encKey[:16], file)
	if err != nil {
		return nil, err
	}

	//Getting the Content
	ContentVerified := CheckMac(file.Content, macKey[:16])
	if !ContentVerified {
		return nil, err
	}
	content, err = DecryptContent(file.Content, encKey[:16], content)
	if err != nil {
		return nil, err
	}

	//If the file is not the last file in the linked list, then iterate thorugh all the files and get the content
	var tempFile File
	tempFile.Next = file.Next
	var tempContent []byte
	for tempFile.Next != uuid.Nil {
		//Getting the TempFile
		Verified := CheckMac(tempFile.Next, macKey[:16])
		if !Verified {
			return nil, err
		}
		tempFile, err = DecryptFile(tempFile.Next, encKey[:16], tempFile)
		if err != nil {
			return nil, err
		}

		//Getting the Content
		ContentVerified := CheckMac(tempFile.Content, macKey[:16])
		if !ContentVerified {
			return nil, err
		}
		tempContent, err = DecryptContent(tempFile.Content, encKey[:16], tempContent)
		if err != nil {
			return nil, err
		}
		content = append(content, tempContent...)
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}

// Helper Functions
// Check if username exist
func CheckExist(username string) bool {
	test, _ := uuid.FromBytes(userlib.Hash([]byte(username))[:16])

	_, Exist := userlib.DatastoreGet(test) //if False means doesn't exist

	return Exist
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	if CheckExist(username) {
		return nil, errors.New("username already exists")
	}

	var userdata User
	userdata.Username = username
	userdata.FileMap = make(map[string]uuid.UUID)
	userdata.FileSalt = make(map[string][]byte)
	SourceKey := userlib.Argon2Key([]byte(password), []byte(username), 16) //source key
	IV := userlib.RandomBytes(16)

	ByteUser, _ := json.Marshal(userdata)
	encKey, _ := userlib.HashKDF(SourceKey, []byte("encryption"))
	macKey, _ := userlib.HashKDF(SourceKey, []byte("mac"))

	EncByteUserStruct := userlib.SymEnc(encKey[:16], IV, ByteUser)
	Hmac_tag, _ := userlib.HMACEval(macKey[:16], EncByteUserStruct)
	EncThenMac := append(Hmac_tag, EncByteUserStruct...) //EncThenMac = Tag||M

	uuidgen, _ := uuid.FromBytes(userlib.Hash([]byte(username)))
	userlib.DatastoreSet(uuidgen, EncThenMac) //HMAC tag at the first 64bytes
	return &userdata, nil
}

func StoreContentToDatastore(id userlib.UUID, data []byte, encKey []byte, macKey []byte) (err error) {
	EncContent, _ := json.Marshal(data)
	IV := userlib.RandomBytes(16)
	EncData := userlib.SymEnc(encKey[:16], IV, EncContent)
	Hmac_tag, _ := userlib.HMACEval(macKey[:16], EncData)
	EncThenMac := append(Hmac_tag, EncData...)
	userlib.DatastoreSet(id, EncThenMac)
	return nil
}
func StoreFileToDatastore(id userlib.UUID, data File, encKey []byte, macKey []byte) (err error) {
	EncFile, _ := json.Marshal(data)
	IV := userlib.RandomBytes(16)
	EncData := userlib.SymEnc(encKey[:16], IV, EncFile)
	Hmac_tag, _ := userlib.HMACEval(macKey[:16], EncData)
	EncThenMac := append(Hmac_tag, EncData...)
	userlib.DatastoreSet(id, EncThenMac)
	return nil
}

func CheckMac(id userlib.UUID, macKey []byte) (varified bool) {
	EncThenMac, ok := userlib.DatastoreGet(id)
	if !ok {
		return false
		//no such UUID
	}
	Hmac_tag, _ := userlib.HMACEval(macKey[:16], EncThenMac[64:])
	if !userlib.HMACEqual(EncThenMac[:64], Hmac_tag) {
		return false
	} //tag not same
	return true
}

func DecryptContent(id userlib.UUID, encKey []byte, data []byte) (result []byte, err error) {
	EncThenMac, ok := userlib.DatastoreGet(id)
	if !ok {
		return data, errors.New("UUID doesn't exist")
	} //No Such UUID
	DecData := userlib.SymDec(encKey[:16], EncThenMac[64:])
	err = json.Unmarshal(DecData, &data)
	return data, err
}
func DecryptFile(id userlib.UUID, encKey []byte, data File) (result File, err error) {
	EncThenMac, ok := userlib.DatastoreGet(id)
	if !ok {
		return data, errors.New("UUID doesn't exist")
	} //No Such UUID
	DecData := userlib.SymDec(encKey[:16], EncThenMac[64:])
	err = json.Unmarshal(DecData, &data)
	return data, err
}
