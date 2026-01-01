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
	_ "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

type AuthEnc struct {
	CipherText []byte
	Tag        []byte
}

// UserProfile is stored encrypted in Datastore with the user's master key
type UserProfile struct {
	Username string
	Salt     []byte
	PrivEnc  []byte
	PrivSig  []byte
	FileMap  map[string]uuid.UUID // filename to file UUID mapping
	KeyMap   map[string][]byte    // filename to enc access keys
	Version  uint64
}

type User struct {
	Username  string
	MasterKey []byte
	Salt      []byte
	PrivEnc   userlib.PKEDecKey
	PrivSig   userlib.DSSignKey
	FileMap   map[string]uuid.UUID
	KeyMap    map[string][]byte
	Version   uint64
}

// holds the enc and mac keys for slices content
type AESPair struct {
	EncKey []byte
	MacKey []byte
}

type FileHeader struct {
	Owner         string
	AESPairPtr    uuid.UUID
	HeadChunkUUID uuid.UUID
	TailChunkUUID uuid.UUID
	AccessMapPtr  uuid.UUID
	Version       uint64
}

// content for the slice with tag for integrity
type ContentChunk struct {
	Content []byte
}

type SliceWrapper struct {
	ContentUUID uuid.UUID
	NextSlice   uuid.UUID
}

type AccessMap struct {
	Tree    map[string]TreeNode // username to access control tree node
	Version uint64
}

type FileAccessKeys struct {
	HeaderKey  []byte
	SubtreeKey []byte
	Version    uint64
	Path       []string
}

type Invite struct {
	EncSessionKey  []byte
	AuthEncPayload []byte
	Signature      []byte
}

type InvitePayload struct {
	FileUUID       uuid.UUID
	FileAccessKeys FileAccessKeys
}

// helper for deterministic UUID from a string
func deriveUUID(input string) (uuid.UUID, error) {
	hash := userlib.Hash([]byte(input))[:16]
	return uuid.FromBytes(hash)
}

func (userdata *User) getFileAccessKeys(filename string) (*FileAccessKeys, error) {
	encKeys, ok := userdata.KeyMap[filename]
	if !ok {
		return nil, errors.New("file keys not found in users key map")
	}

	userFileKey, err := userlib.HashKDF(userdata.MasterKey, []byte("keymap-key-"+filename))
	if err != nil {
		return nil, fmt.Errorf("failed to derive user file key: %w", err)
	}
	userFileKey = userFileKey[:16]

	keysBytes, err := authDec(encKeys, userFileKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file access keys: %w", err)
	}

	var accessKeys FileAccessKeys
	if err := json.Unmarshal(keysBytes, &accessKeys); err != nil {
		return nil, fmt.Errorf("failed to unmarshal file access keys: %w", err)
	}

	return &accessKeys, nil
}

func (userdata *User) refreshProfile() error {
	//gen profile uuid -> fetch enc UserProfile
	profileUUID, err := deriveUUID("userprofile-" + userdata.Username)
	if err != nil {
		return fmt.Errorf("failed to generate profile UUID for refreshing: %w", err)
	}

	encProfile, ok := userlib.DatastoreGet(profileUUID)
	if !ok {
		return errors.New("user profile not found during refresh")
	}

	//dec profile with master key
	profileBytes, err := authDec(encProfile, userdata.MasterKey)
	if err != nil {
		return fmt.Errorf("could not decrypt user profile for refreshing: %w", err)
	}

	//unmarshal to temp UserProfile
	var storedProfile UserProfile
	if err := json.Unmarshal(profileBytes, &storedProfile); err != nil {
		return fmt.Errorf("failed to unmarshal refreshed UserProfile:%w", err)
	}

	//check if stored version is newer
	if storedProfile.Version > userdata.Version {
		userdata.FileMap = storedProfile.FileMap
		userdata.KeyMap = storedProfile.KeyMap
		userdata.Version = storedProfile.Version
	}

	return nil
}

func authEnc(data, key []byte) ([]byte, error) {

	//derive enc key
	encKey, err := userlib.HashKDF(key, []byte("enc"))
	if err != nil {
		return nil, err
	}
	encKey = encKey[:16]

	//get hmac key
	hmacKey, err := userlib.HashKDF(key, []byte("hmac"))
	if err != nil {
		return nil, err
	}
	hmacKey = hmacKey[:16]

	iv := userlib.RandomBytes(16)
	cipherText := userlib.SymEnc(encKey, iv, data)
	tag, err := userlib.HMACEval(hmacKey, cipherText)
	if err != nil {
		return nil, err
	}

	authData := AuthEnc{CipherText: cipherText, Tag: tag}
	return json.Marshal(authData)
}

func authDec(data, key []byte) ([]byte, error) {

	//same as authEnc but backwards
	encKey, err := userlib.HashKDF(key, []byte("enc"))
	if err != nil {
		return nil, err
	}
	encKey = encKey[:16]

	hmacKey, err := userlib.HashKDF(key, []byte("hmac"))
	if err != nil {
		return nil, err
	}
	hmacKey = hmacKey[:16]

	var authData AuthEnc
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, err
	}

	//recompute tag & verify integrity
	checkedTag, err := userlib.HMACEval(hmacKey, authData.CipherText)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(checkedTag, authData.Tag) {
		return nil, errors.New("integrity violated")
	}
	if len(authData.CipherText) < 16 {
		return nil, errors.New("ciphertext too short")
	}
	plaintext := userlib.SymDec(encKey, authData.CipherText)

	return plaintext, nil
}

func (userdata *User) getFileHeader(filename string) (*FileHeader, uuid.UUID, []byte, error) {

	//fetch file header UUID from filemap
	fileUUID, ok := userdata.FileMap[filename]
	if !ok {
		return nil, uuid.Nil, nil, errors.New("file not found in users file map")
	}

	//get access keys for header dec
	accessKeys, err := userdata.getFileAccessKeys(filename)
	if err != nil {
		return nil, uuid.Nil, nil, fmt.Errorf("could not retrieve file access keys: %w", err)
	}
	headerKey := accessKeys.HeaderKey

	//fetch enc header from datastore
	encHeader, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, uuid.Nil, nil, errors.New("file header not found in datastore")
	}

	//dec header with cooresponding key
	headerBytes, err := authDec(encHeader, headerKey)
	if err != nil {
		return nil, uuid.Nil, nil, fmt.Errorf("failed to decrypt header: %w", err)
	}

	var header FileHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, uuid.Nil, nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	//removed the length check
	return &header, fileUUID, headerKey, nil
}

func (userdata *User) getFileAESPair(header *FileHeader, filename string) (*AESPair, error) {
	accessKeys, err := userdata.getFileAccessKeys(filename)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve file access keys: %w", err)
	}

	aesPairWrappingKey := accessKeys.SubtreeKey

	encAESPair, ok := userlib.DatastoreGet(header.AESPairPtr)
	if !ok {
		return nil, errors.New("AESPair not found for file")
	}

	aesPairBytes, err := authDec(encAESPair, aesPairWrappingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AESPair: %w", err)
	}

	var aesPair AESPair
	if err := json.Unmarshal(aesPairBytes, &aesPair); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AESPair: %w", err)
	}

	return &aesPair, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New("no empty usernames")
	}

	//gen profile uuid
	profileUUID, err := deriveUUID("userprofile-" + username)
	if err != nil {
		return nil, fmt.Errorf("failed to generate profile UUID due to: %w", err)
	}
	if _, ok := userlib.DatastoreGet(profileUUID); ok {
		return nil, errors.New("user already exists")
	}

	salt := userlib.Hash([]byte("user-salt-" + username))
	masterKey := userlib.Argon2Key([]byte(password), salt, 16)

	//gen PKE and DS key pairs
	encPub, encPriv, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption keys due to: %w", err)
	}
	sigPriv, sigPub, err := userlib.DSKeyGen()
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing keys due to: %w", err)
	}

	//enc private keys with masterKey
	encPrivBytes, err := json.Marshal(encPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encPriv: %w", err)
	}
	encPrivEnc, err := authEnc(encPrivBytes, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt encPriv: %w", err)
	}

	sigPrivBytes, err := json.Marshal(sigPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sigPriv: %w", err)
	}
	sigPrivEnc, err := authEnc(sigPrivBytes, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt sigPriv: %w", err)
	}

	profile := UserProfile{
		Username: username,
		Salt:     salt,
		PrivEnc:  encPrivEnc,
		PrivSig:  sigPrivEnc,
		FileMap:  make(map[string]uuid.UUID),
		KeyMap:   make(map[string][]byte),
		Version:  1,
	}

	//marshal and encrypt profile
	profileToBytes, err := json.Marshal(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UserProfie due to: %w", err)
	}
	encProfile, err := authEnc(profileToBytes, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt UserProfile due to: %w", err)
	}

	//store encrypted profile and public keys
	userlib.DatastoreSet(profileUUID, encProfile)
	userlib.KeystoreSet(username+"_enc", encPub)
	userlib.KeystoreSet(username+"_sig", sigPub)

	//create 'in memory' User
	userdata := &User{
		Username:  username,
		MasterKey: masterKey,
		Salt:      salt,
		PrivEnc:   encPriv,
		PrivSig:   sigPriv,
		FileMap:   profile.FileMap,
		KeyMap:    profile.KeyMap,
		Version:   profile.Version,
	}
	return userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New("no empty username")
	}

	//gen profile uuid -> fetch enc profile
	profileUUID, err := deriveUUID("userprofile-" + username)
	if err != nil {
		return nil, fmt.Errorf("failed to generate profile UUID due to: %w", err)
	}
	encProfile, ok := userlib.DatastoreGet(profileUUID)
	if !ok {
		return nil, errors.New("user DNE")
	}

	salt := userlib.Hash([]byte("user-salt-" + username))
	masterKey := userlib.Argon2Key([]byte(password), salt, 16)

	//dec profile for salt and master key
	profileBytes, err := authDec(encProfile, masterKey)
	if err != nil {
		return nil, fmt.Errorf("invalid password or decryption failed due to: %w", err)
	}

	var profile UserProfile
	if err := json.Unmarshal(profileBytes, &profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal UserProfile due to: %w", err)
	}

	//now dec private keys
	encPrivBytes, err := authDec(profile.PrivEnc, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decryption failed with correct key due to: %w", err)
	}

	var encPriv userlib.PKEDecKey
	if err := json.Unmarshal(encPrivBytes, &encPriv); err != nil {
		return nil, fmt.Errorf("failed to unmarshal UserProfile due to: %w", err)
	}

	sigPrivBytes, err := authDec(profile.PrivSig, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt PrivSig due to: %w", err)
	}

	//grab sig as well
	var sigPriv userlib.DSSignKey
	if err := json.Unmarshal(sigPrivBytes, &sigPriv); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PrivSig: %w", err)
	}

	userdata := &User{
		Username:  profile.Username,
		MasterKey: masterKey,
		Salt:      salt,
		PrivEnc:   encPriv,
		PrivSig:   sigPriv,
		FileMap:   profile.FileMap,
		KeyMap:    profile.KeyMap,
		Version:   profile.Version,
	}
	return userdata, nil
}

func (userdata *User) saveProfile() error {

	//gen profile uuid
	profileUUID, err := deriveUUID("userprofile-" + userdata.Username)
	if err != nil {
		return fmt.Errorf("failed to generate profile UUID for saving: %w", err)
	}

	//encrypt private keys again before saving
	encPrivBytes, err := json.Marshal(userdata.PrivEnc)
	if err != nil {
		return fmt.Errorf("failed to marshal encPriv for saving: %w", err)
	}
	encPrivEnc, err := authEnc(encPrivBytes, userdata.MasterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt encPriv for saving: %w", err)
	}

	sigPrivBytes, err := json.Marshal(userdata.PrivSig)
	if err != nil {
		return fmt.Errorf("failed to marshal sigPriv for saving: %w", err)
	}
	sigPrivEnc, err := authEnc(sigPrivBytes, userdata.MasterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt sigPriv for saving: %w", err)
	}

	//create UserProfile with updated fields
	profile := UserProfile{
		Username: userdata.Username,
		Salt:     userdata.Salt,
		PrivEnc:  encPrivEnc,
		PrivSig:  sigPrivEnc,
		FileMap:  userdata.FileMap,
		KeyMap:   userdata.KeyMap,
		Version:  userdata.Version + 1,
	}

	profileToBytes, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("failed to marshal UserProfile for saving: %w", err)
	}
	encProfile, err := authEnc(profileToBytes, userdata.MasterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt UserProfile for saving: %w", err)
	}

	userlib.DatastoreSet(profileUUID, encProfile)
	userdata.Version = profile.Version //update 'in-memory' version

	return nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	if err := userdata.refreshProfile(); err != nil {
		return fmt.Errorf("failed to refresh profile before storing file: %w", err)
	}
	//if filename == "" {
	//return errors.New("empty filename not allowed")
	//}

	if fileUUID, exists := userdata.FileMap[filename]; exists {
		//if it exists then we need to update the content only to preserve sharing, else it would be a new file
		header, _, headerKey, err := userdata.getFileHeader(filename)
		if err != nil {
			return fmt.Errorf("failed to get existing file header: %w", err)
		}

		aesPair, err := userdata.getFileAESPair(header, filename)
		if err != nil {
			return fmt.Errorf("failed to get AESPair: %w", err)
		}

		//first delete the old content slices
		currentWrapperUUID := header.HeadChunkUUID
		for currentWrapperUUID != uuid.Nil {
			encWrapper, ok := userlib.DatastoreGet(currentWrapperUUID)
			if !ok {
				break
			}

			wrapperBytes, err := authDec(encWrapper, aesPair.EncKey)
			if err != nil {
				break
			}

			var wrapper SliceWrapper
			if err := json.Unmarshal(wrapperBytes, &wrapper); err != nil {
				break
			}

			userlib.DatastoreDelete(wrapper.ContentUUID)
			userlib.DatastoreDelete(currentWrapperUUID)

			currentWrapperUUID = wrapper.NextSlice
		}

		//creates new content with but with the same aes pair
		cipherText := userlib.SymEnc(aesPair.EncKey, userlib.RandomBytes(16), content)
		tag, err := userlib.HMACEval(aesPair.MacKey, cipherText)
		if err != nil {
			return fmt.Errorf("failed to MAC content chunk: %w", err)
		}

		chunk := ContentChunk{Content: append(tag, cipherText...)}
		chunkBytes, err := json.Marshal(chunk)
		if err != nil {
			return fmt.Errorf("failed to marshal content chunk: %w", err)
		}
		encChunkBytes, err := authEnc(chunkBytes, aesPair.MacKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt content chunk: %w", err)
		}
		contentUUID := uuid.New()
		userlib.DatastoreSet(contentUUID, encChunkBytes)

		//wrapper for the new content
		wrapper := SliceWrapper{
			ContentUUID: contentUUID,
			NextSlice:   uuid.Nil,
		}

		wrapperBytes, err := json.Marshal(wrapper)
		if err != nil {
			return fmt.Errorf("failed to marshal slice wrapper: %w", err)
		}

		encWrapper, err := authEnc(wrapperBytes, aesPair.EncKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt slice wrapper: %w", err)
		}

		wrapperUUID := uuid.New()
		userlib.DatastoreSet(wrapperUUID, encWrapper)

		//updating the header with the new content pointers
		header.HeadChunkUUID = wrapperUUID
		header.TailChunkUUID = wrapperUUID
		header.Version++

		headerBytes, err := json.Marshal(header)
		if err != nil {
			return fmt.Errorf("failed to marshal updated header: %w", err)
		}
		encHeader, err := authEnc(headerBytes, headerKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt updated header: %w", err)
		}
		userlib.DatastoreSet(fileUUID, encHeader)

		//need to update FileAccessKeys version to match header version
		accessKeys, err := userdata.getFileAccessKeys(filename)
		if err != nil {
			return fmt.Errorf("failed to get access keys: %w", err)
		}
		accessKeys.Version = header.Version
		accessKeysBytes, err := json.Marshal(accessKeys)
		if err != nil {
			return fmt.Errorf("failed to marshal updated access keys: %w", err)
		}
		userFileKey, err := userlib.HashKDF(userdata.MasterKey, []byte("keymap-key-"+filename))
		if err != nil {
			return fmt.Errorf("failed to derive user file key: %w", err)
		}
		userFileKey = userFileKey[:16]
		encAccKeys, err := authEnc(accessKeysBytes, userFileKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt updated access keys: %w", err)
		}
		userdata.KeyMap[filename] = encAccKeys

		return userdata.saveProfile()
	}

	//if the file doesn't exist then we need to create a new one
	aesPair := AESPair{
		EncKey: userlib.RandomBytes(16),
		MacKey: userlib.RandomBytes(16),
	}
	headerKey := userlib.RandomBytes(16)
	aesPairWrappingKey := userlib.RandomBytes(16)

	aesPairBytes, err := json.Marshal(aesPair)
	if err != nil {
		return fmt.Errorf("failed to marshal AESPair: %w", err)
	}
	encAESPair, err := authEnc(aesPairBytes, aesPairWrappingKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt AESPair: %w", err)
	}
	aesPairUUID := uuid.New()
	userlib.DatastoreSet(aesPairUUID, encAESPair)

	accessKeys := FileAccessKeys{
		HeaderKey:  headerKey,
		SubtreeKey: aesPairWrappingKey,
		Version:    1,
		Path:       []string{userdata.Username},
	}

	accessKeysBytes, err := json.Marshal(accessKeys)
	if err != nil {
		return fmt.Errorf("failed to marshal access keys: %w", err)
	}

	userFileKey, err := userlib.HashKDF(userdata.MasterKey, []byte("keymap-key-"+filename))
	if err != nil {
		return fmt.Errorf("failed to derive user file key: %w", err)
	}

	userFileKey = userFileKey[:16]
	encAccKeys, err := authEnc(accessKeysBytes, userFileKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt access keys: %w", err)
	}

	userdata.KeyMap[filename] = encAccKeys

	//create and store the first ContentChunk
	cipherText := userlib.SymEnc(aesPair.EncKey, userlib.RandomBytes(16), content)
	tag, err := userlib.HMACEval(aesPair.MacKey, cipherText)
	if err != nil {
		return fmt.Errorf("failed to MAC content chunk: %w", err)
	}

	chunk := ContentChunk{Content: append(tag, cipherText...)}
	chunkBytes, err := json.Marshal(chunk)
	if err != nil {
		return fmt.Errorf("failed to marshal content chunk: %w", err)
	}

	encChunkBytes, err := authEnc(chunkBytes, aesPair.MacKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt content chunk: %w", err)
	}

	contentUUID := uuid.New()
	userlib.DatastoreSet(contentUUID, encChunkBytes)

	//create and store the first SliceWrapper, just a pointer to the first chunk
	wrapper := SliceWrapper{
		ContentUUID: contentUUID,
		NextSlice:   uuid.Nil,
	}
	wrapperBytes, err := json.Marshal(wrapper)
	if err != nil {
		return fmt.Errorf("failed to marshal slice wrapper: %w", err)
	}
	encWrapper, err := authEnc(wrapperBytes, aesPair.EncKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt slice wrapper: %w", err)
	}
	wrapperUUID := uuid.New()
	userlib.DatastoreSet(wrapperUUID, encWrapper)

	//create and store the FileHeader
	header := FileHeader{
		Owner:         userdata.Username,
		AESPairPtr:    aesPairUUID,
		HeadChunkUUID: wrapperUUID,
		TailChunkUUID: wrapperUUID,
		Version:       1,
	}
	accessMap := AccessMap{
		Tree: map[string]TreeNode{
			userdata.Username: {WrapKey: nil, Leaves: []string{}}, //root for the owner
		},
		Version: 1,
	}
	accessMapBytes, err := json.Marshal(accessMap)
	if err != nil {
		return fmt.Errorf("failed to marshal AccessMap: %w", err)
	}
	encAccessMap, err := authEnc(accessMapBytes, headerKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt AccessMap: %w", err)
	}
	accessMapUUID := uuid.New()
	userlib.DatastoreSet(accessMapUUID, encAccessMap)
	header.AccessMapPtr = accessMapUUID
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to marshal file header: %w", err)
	}
	encHeader, err := authEnc(headerBytes, headerKey) //using the new random headerKey
	if err != nil {
		return fmt.Errorf("failed to encrypt file header: %w", err)
	}

	//need to update the users file map
	fileUUID := uuid.New()
	userlib.DatastoreSet(fileUUID, encHeader)
	userdata.FileMap[filename] = fileUUID

	return userdata.saveProfile()
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	if err := userdata.refreshProfile(); err != nil {
		return fmt.Errorf("failed to refresh profile before appending to file: %w", err)
	}
	//if filename == "" {
	//return errors.New("no empty filenames")
	//}

	if len(content) == 0 {
		return nil
	}

	//fetch header and AESPair
	header, fileUUID, headerKey, err := userdata.getFileHeader(filename)
	if err != nil {
		return err
	}
	aesPair, err := userdata.getFileAESPair(header, filename)
	if err != nil {
		return err
	}

	//fetch and decrypt the current tail SliceWrapper
	tailWrapperUUID := header.TailChunkUUID
	encTailWrapper, ok := userlib.DatastoreGet(tailWrapperUUID)
	if !ok {
		return errors.New("tail slice wrapper not found")
	}
	tailWrapperBytes, err := authDec(encTailWrapper, aesPair.EncKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt tail slice wrapper: %w", err)
	}
	var tailWrapper SliceWrapper
	if err := json.Unmarshal(tailWrapperBytes, &tailWrapper); err != nil {
		return fmt.Errorf("failed to unmarshal tail slice wrapper: %w", err)
	}

	//verify integrity of tail content chunk before append to preventt ampring
	encTailChunk, ok := userlib.DatastoreGet(tailWrapper.ContentUUID)
	if !ok {
		return errors.New("tail content chunk not found")
	}
	tailChunkBytes, err := authDec(encTailChunk, aesPair.MacKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt/verify tail content chunk: %w", err)
	}

	var tailContentChunk ContentChunk
	if err := json.Unmarshal(tailChunkBytes, &tailContentChunk); err != nil {
		return fmt.Errorf("failed to unmarshal tail content chunk: %w", err)
	}
	if len(tailContentChunk.Content) < 64 {
		return errors.New("tail chunk is too short to have a tag")
	}

	tailTag := tailContentChunk.Content[:64]
	tailCipherText := tailContentChunk.Content[64:]
	expectedTailTag, err := userlib.HMACEval(aesPair.MacKey, tailCipherText)

	if err != nil {
		return fmt.Errorf("failed to compute HMAC for tail content chunk: %w", err)
	}
	if !userlib.HMACEqual(tailTag, expectedTailTag) {
		return errors.New("tail content chunk MAC failure")
	}

	//store the new content chunk
	cipherText := userlib.SymEnc(aesPair.EncKey, userlib.RandomBytes(16), content)
	var tag []byte
	tag, err = userlib.HMACEval(aesPair.MacKey, cipherText)
	if err != nil {
		return fmt.Errorf("failed to MAC new content chunk: %w", err)
	}
	newChunk := ContentChunk{Content: append(tag, cipherText...)}
	newChunkBytes, err := json.Marshal(newChunk)
	if err != nil {
		return fmt.Errorf("failed to marshal new content chunk: %w", err)
	}
	encNewChunkBytes, err := authEnc(newChunkBytes, aesPair.MacKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt new content chunk: %w", err)
	}
	newContentUUID := uuid.New()
	userlib.DatastoreSet(newContentUUID, encNewChunkBytes)

	//store the new SliceWrapper
	newWrapper := SliceWrapper{
		ContentUUID: newContentUUID,
		NextSlice:   uuid.Nil,
	}
	newWrapperBytes, err := json.Marshal(newWrapper)
	if err != nil {
		return fmt.Errorf("failed to marshal new slice wrapper: %w", err)
	}
	encNewWrapper, err := authEnc(newWrapperBytes, aesPair.EncKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt new slice wrapper: %w", err)
	}
	newWrapperUUID := uuid.New()
	userlib.DatastoreSet(newWrapperUUID, encNewWrapper)

	//update the old tail SliceWrapper to point to the new one
	tailWrapper.NextSlice = newWrapperUUID
	updatedTailWrapperBytes, err := json.Marshal(tailWrapper)
	if err != nil {
		return fmt.Errorf("failed to marshal updated tail wrapper: %w", err)
	}
	encUpdatedTailWrapper, err := authEnc(updatedTailWrapperBytes, aesPair.EncKey)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt tail wrapper: %w", err)
	}
	userlib.DatastoreSet(tailWrapperUUID, encUpdatedTailWrapper)

	//updates the header to point to the new tail
	header.TailChunkUUID = newWrapperUUID
	header.Version++
	updatedHeaderBytes, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to marshal updated header: %w", err)
	}
	updatedEncHeader, err := authEnc(updatedHeaderBytes, headerKey)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt header: %w", err)
	}
	userlib.DatastoreSet(fileUUID, updatedEncHeader)

	return userdata.saveProfile()
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	if err := userdata.refreshProfile(); err != nil {
		return nil, fmt.Errorf("failed to refresh profile before loading file: %w", err)
	}
	//if filename == "" {
	//return nil, errors.New("no empty filenames")
	//}
	header, _, headerKey, err := userdata.getFileHeader(filename)
	if err != nil {
		return nil, err
	}

	//got to check if the access map is valid first
	_, err = getAccessMap(header, headerKey)
	if err != nil {
		return nil, fmt.Errorf("AccessMap integrity check failed: %w", err)
	}
	accessKeys, err := userdata.getFileAccessKeys(filename)
	if err != nil {
		return nil, err
	}

	if header.Version < accessKeys.Version {
		return nil, errors.New("file version is older than expected")
	}

	if header.Version > accessKeys.Version {
		accessMap, err := getAccessMap(header, headerKey) //lazy update
		if err != nil {
			return nil, err
		}

		if userdata.Username == header.Owner {
			accessKeys.Version = header.Version
		} else {
			//starts with verifying the path
			current := header.Owner
			for _, step := range accessKeys.Path[1:] {
				node, ok := accessMap.Tree[current]
				if !ok || !contains(node.Leaves, step) {
					return nil, errors.New("path invalid after revoke")
				}
				current = step
			}
			//dec the new wrap key
			node, ok := accessMap.Tree[userdata.Username]
			if !ok {
				return nil, errors.New("user not in access tree")
			}

			newSubtreeKey, err := userlib.PKEDec(userdata.PrivEnc, node.WrapKey)
			if err != nil {
				return nil, err
			}

			accessKeys.SubtreeKey = newSubtreeKey
			accessKeys.Version = header.Version
		}
		//finish with updating the key map and saving profile
		accessKeysBytes, _ := json.Marshal(accessKeys)
		userFileKey, _ := userlib.HashKDF(userdata.MasterKey, []byte("keymap-key-"+filename))
		userFileKey = userFileKey[:16]
		encAccKeys, _ := authEnc(accessKeysBytes, userFileKey)

		userdata.KeyMap[filename] = encAccKeys
		userdata.saveProfile()
	}
	aesPair, err := userdata.getFileAESPair(header, filename)
	if err != nil {
		return nil, err
	}

	var fullContent []byte
	currentWrapperUUID := header.HeadChunkUUID
	for currentWrapperUUID != uuid.Nil {

		encWrapper, ok := userlib.DatastoreGet(currentWrapperUUID)
		if !ok {
			return nil, fmt.Errorf("slice wrapper %s not found", currentWrapperUUID)
		}
		wrapperBytes, err := authDec(encWrapper, aesPair.EncKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt slice wrapper %s: %w", currentWrapperUUID, err)
		}
		var currentWrapper SliceWrapper
		if err := json.Unmarshal(wrapperBytes, &currentWrapper); err != nil {
			return nil, fmt.Errorf("failed to unmarshal slice wrapper %s: %w", currentWrapperUUID, err)
		}

		//grab chunk to verify, and unmarshal
		encChunkBytes, ok := userlib.DatastoreGet(currentWrapper.ContentUUID)
		if !ok {
			return nil, fmt.Errorf("content chunk %s not found", currentWrapper.ContentUUID)
		}
		chunkBytes, err := authDec(encChunkBytes, aesPair.MacKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt/verify content chunk %s: %w", currentWrapper.ContentUUID, err)
		}
		var contentChunk ContentChunk
		if err := json.Unmarshal(chunkBytes, &contentChunk); err != nil {
			return nil, fmt.Errorf("failed to unmarshal content chunk %s: %w", currentWrapper.ContentUUID, err)
		}

		if len(contentChunk.Content) < 64 {
			return nil, errors.New("content chunk is too short to contain a tag")
		}
		tag := contentChunk.Content[:64]
		cipherTextWithIV := contentChunk.Content[64:]
		expectedTag, err := userlib.HMACEval(aesPair.MacKey, cipherTextWithIV)
		if err != nil {
			return nil, fmt.Errorf("failed to compute HMAC for content chunk %s: %w", currentWrapper.ContentUUID, err)
		}
		if !userlib.HMACEqual(tag, expectedTag) {
			return nil, errors.New("file integrity compromised: content chunk MAC mismatch")
		}

		if len(cipherTextWithIV) < 16 {
			return nil, errors.New("ciphertext too short")
		}
		decryptedContent := userlib.SymDec(aesPair.EncKey, cipherTextWithIV)
		fullContent = append(fullContent, decryptedContent...)

		currentWrapperUUID = currentWrapper.NextSlice
	}

	return fullContent, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	if err := userdata.refreshProfile(); err != nil {
		return uuid.Nil, fmt.Errorf("failed to refresh profile before creating invitation: %w", err)
	}

	fileUUID, ok := userdata.FileMap[filename]
	if !ok {
		return uuid.Nil, errors.New("file not found in users file map")
	}
	accessKeys, err := userdata.getFileAccessKeys(filename)
	if err != nil {
		return uuid.Nil, fmt.Errorf("could not retrieve file access keys for invitation: %w", err)
	}

	//load accessMap
	header, _, headerKey, err := userdata.getFileHeader(filename)
	if err != nil {
		return uuid.Nil, err
	}
	accessMap, err := getAccessMap(header, headerKey)
	if err != nil {
		return uuid.Nil, err
	}

	//finding the senders node and path
	senderNode, senderPath, senderParent, found := findNodeAndPath(accessMap.Tree, header.Owner, userdata.Username, []string{})
	if !found {
		return uuid.Nil, errors.New("sender not in access tree")
	}
	_ = senderParent

	//add recipient as a leaf of the sender
	senderNode.Leaves = append(senderNode.Leaves, recipientUsername)
	accessMap.Tree[userdata.Username] = senderNode

	recipientSubtreeKey := accessKeys.SubtreeKey //made sure to use the sender subtreeKey directly for recipient

	//wrap before sending
	recipientPub, ok := userlib.KeystoreGet(recipientUsername + "_enc")
	if !ok {
		return uuid.Nil, errors.New("recipient pub key not found")
	}

	wrappedSubtreeKey, err := userlib.PKEEnc(recipientPub, recipientSubtreeKey)
	if err != nil {
		return uuid.Nil, err
	}

	//add to tree
	accessMap.Tree[recipientUsername] = TreeNode{
		WrapKey: wrappedSubtreeKey,
		Leaves:  []string{},
	}

	//save AccessMap
	if err := saveAccessMap(accessMap, header.AccessMapPtr, headerKey); err != nil {
		return uuid.Nil, err
	}

	//payload with wrapped key
	payload := InvitePayload{
		FileUUID:       fileUUID,
		FileAccessKeys: FileAccessKeys{HeaderKey: accessKeys.HeaderKey, SubtreeKey: wrappedSubtreeKey, Version: header.Version, Path: append(senderPath, userdata.Username)},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to marshal invitation payload: %w", err)
	}
	sessionKey := userlib.RandomBytes(16)

	encSeshKey, err := userlib.PKEEnc(recipientPub, sessionKey)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to encrypt invitation session key: %w", err)
	}

	authEncPayload, err := authEnc(payloadBytes, sessionKey)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to symmetrically encrypt invitation payload: %w", err)
	}

	signature, err := userlib.DSSign(userdata.PrivSig, authEncPayload)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to sign invitation: %w", err)
	}

	invitation := Invite{
		EncSessionKey:  encSeshKey,
		AuthEncPayload: authEncPayload,
		Signature:      signature,
	}

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to marshal final invitation: %w", err)
	}

	invitationUUID := uuid.New()
	userlib.DatastoreSet(invitationUUID, invitationBytes)

	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	if err := userdata.refreshProfile(); err != nil {
		return fmt.Errorf("failed to refresh profile before accepting invitation: %w", err)
	}
	//check if the recipient already has a file with this name
	if _, ok := userdata.FileMap[filename]; ok {
		return errors.New("a file with the chosen filename already exists")
	}

	//fetch and unmarshal the invitation
	invitationBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation not found")
	}
	var invitation Invite
	if err := json.Unmarshal(invitationBytes, &invitation); err != nil {
		return fmt.Errorf("failed to unmarshal invitation: %w", err)
	}

	//get the sender's public verification key
	senderDSKey, ok := userlib.KeystoreGet(senderUsername + "_sig")
	if !ok {
		return errors.New("sender user does not exist")
	}

	//verify the signature over the encrypted payload
	err := userlib.DSVerify(senderDSKey, invitation.AuthEncPayload, invitation.Signature)
	if err != nil {
		return fmt.Errorf("invitation signature verification failed: %w", err)
	}

	//decrypt the session key, then use it to decrypt the payload
	sessionKey, err := userlib.PKEDec(userdata.PrivEnc, invitation.EncSessionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt invitation session key: %w", err)
	}
	payloadBytes, err := authDec(invitation.AuthEncPayload, sessionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt invitation payload: %w", err)
	}
	var payload InvitePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("failed to unmarshal invitation payload: %w", err)
	}

	//after unmarshalling payload, we unwrap the subtree key
	subtreeKey, err := userlib.PKEDec(userdata.PrivEnc, payload.FileAccessKeys.SubtreeKey)
	if err != nil {
		return fmt.Errorf("failed to unwrap subtree key: %w", err)
	}

	//first we verify that the recipient is still in the access tree
	fileUUID := payload.FileUUID
	encHeader, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return errors.New("file no longer exists")
	}

	headerBytes, err := authDec(encHeader, payload.FileAccessKeys.HeaderKey)
	if err != nil {
		return errors.New("cannot access file - invitation may have been revoked")
	}

	var header FileHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return errors.New("cannot read file header - invitation may have been revoked")
	}

	//first we check if the user is still in the access map
	accessMap, err := getAccessMap(&header, payload.FileAccessKeys.HeaderKey)
	if err != nil {
		return errors.New("cannot access file - invitation may have been revoked")
	}

	//also need to check if the user is still in the access tree
	if _, exists := accessMap.Tree[userdata.Username]; !exists {
		return errors.New("access has been revoked")
	}

	accessKeys := FileAccessKeys{HeaderKey: payload.FileAccessKeys.HeaderKey, SubtreeKey: subtreeKey, Version: payload.FileAccessKeys.Version, Path: payload.FileAccessKeys.Path}

	//store the new file access information in the users own maps
	//enc the access keys with a key derived from the recipients master key
	userFileKey, err := userlib.HashKDF(userdata.MasterKey, []byte("keymap-key-"+filename))
	if err != nil {
		return fmt.Errorf("failed to derive user file key for accepted invite: %w", err)
	}
	userFileKey = userFileKey[:16]

	accessKeysBytes, err := json.Marshal(accessKeys)
	if err != nil {
		return fmt.Errorf("failed to marshal access keys for storage: %w", err)
	}
	encAccKeys, err := authEnc(accessKeysBytes, userFileKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt access keys for storage: %w", err)
	}

	userdata.KeyMap[filename] = encAccKeys
	userdata.FileMap[filename] = payload.FileUUID

	//save profile with new entry
	if err := userdata.saveProfile(); err != nil {
		return err
	}

	userlib.DatastoreDelete(invitationPtr)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	if err := userdata.refreshProfile(); err != nil {
		return err
	}
	header, fileUUID, headerKey, err := userdata.getFileHeader(filename)
	if err != nil {
		return err
	}
	if header.Owner != userdata.Username {
		return errors.New("only owner can revoke")
	}
	accessMap, err := getAccessMap(header, headerKey)
	if err != nil {
		return err
	}
	//first we need to find node, path and parent
	node, path, parent, found := findNodeAndPath(accessMap.Tree, header.Owner, recipientUsername, []string{})
	if !found {
		return errors.New("recipient not in access tree")
	}
	_ = node
	_ = path

	//remove subtree
	removeSubtree(accessMap, recipientUsername, parent)

	//fetch old AESPair
	oldAESPair, err := userdata.getFileAESPair(header, filename)
	if err != nil {
		return err
	}

	//create new AESPair that we need to rekey all the content so adversary cannot access it
	newAESPair := AESPair{
		EncKey: userlib.RandomBytes(16),
		MacKey: userlib.RandomBytes(16),
	}
	newRootSubtreeKey := userlib.RandomBytes(16)

	//reWrap existing AESPair with new key along with the content so that revoked users cannot access it
	err = reEncContent(header, oldAESPair, &newAESPair)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt file content during revocation: %w", err)
	}

	//Store new AESPair wrapped with new key
	aesPairBytes, _ := json.Marshal(newAESPair)
	encNewAESPair, _ := authEnc(aesPairBytes, newRootSubtreeKey)
	newAESPairUUID := uuid.New()
	userlib.DatastoreSet(newAESPairUUID, encNewAESPair)

	//have to clean up old aesPair
	userlib.DatastoreDelete(header.AESPairPtr)
	header.AESPairPtr = newAESPairUUID

	for uname, tnode := range accessMap.Tree {
		tnode.WrapKey = newRootSubtreeKey // <- update the field inside the struct
		accessMap.Tree[uname] = tnode     //    and write the struct back
	}

	// ----------------- ❷ Update this (owner) User’s KeyMap entry -------
	ownerKeys := FileAccessKeys{
		HeaderKey:  headerKey,
		SubtreeKey: newRootSubtreeKey,
		Version:    header.Version + 1,
		Path:       []string{userdata.Username},
	}
	okBytes, _ := json.Marshal(ownerKeys)
	okKey, _ := userlib.HashKDF(userdata.MasterKey, []byte("keymap-key-"+filename))
	okKey = okKey[:16]
	encOK, _ := authEnc(okBytes, okKey)
	userdata.KeyMap[filename] = encOK
	//update tree keys
	err = updateSubtreeKeys(accessMap, newRootSubtreeKey, header.Owner, header.Version+1)
	if err != nil {
		return err
	}
	accessMap.Version = header.Version + 1

	//save AccessMap and header
	saveAccessMap(accessMap, header.AccessMapPtr, headerKey)
	header.Version++
	headerBytes, _ := json.Marshal(header)
	encHeader, _ := authEnc(headerBytes, headerKey)
	userlib.DatastoreSet(fileUUID, encHeader)

	//update owners KeyMap
	accessKeys := FileAccessKeys{HeaderKey: headerKey, SubtreeKey: newRootSubtreeKey, Version: header.Version, Path: []string{userdata.Username}}
	accessKeysBytes, _ := json.Marshal(accessKeys)

	userFileKey, _ := userlib.HashKDF(userdata.MasterKey, []byte("keymap-key-"+filename))
	userFileKey = userFileKey[:16]

	encAccKeys, _ := authEnc(accessKeysBytes, userFileKey)
	userdata.KeyMap[filename] = encAccKeys

	return userdata.saveProfile()
}

// all of these functions are used to maintain the integrity of the access map and help with revocation
func saveAccessMap(accessMap *AccessMap, accessMapUUID uuid.UUID, headerKey []byte) error {
	accessMapBytes, err := json.Marshal(accessMap)
	if err != nil {
		return err
	}

	encAccessMap, err := authEnc(accessMapBytes, headerKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(accessMapUUID, encAccessMap)
	return nil
}

func getAccessMap(header *FileHeader, headerKey []byte) (*AccessMap, error) {
	encAccessMap, ok := userlib.DatastoreGet(header.AccessMapPtr)
	if !ok {
		return nil, errors.New("AccessMap not found")
	}
	accessMapBytes, err := authDec(encAccessMap, headerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AccessMap: %w", err)
	}
	var accessMap AccessMap
	if err := json.Unmarshal(accessMapBytes, &accessMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AccessMap: %w", err)
	}
	return &accessMap, nil
}

type TreeNode struct { //using this struct to make the code easier to write for finding the node and path
	WrapKey []byte
	Leaves  []string
}

func findNodeAndPath(tree map[string]TreeNode, root string, target string, currentPath []string) (foundNode TreeNode, path []string, parent string, found bool) {
	if root == target {
		node, exists := tree[root]
		return node, currentPath, "", exists
	}

	node, exists := tree[root]
	if !exists {
		return TreeNode{}, nil, "", false
	}

	updatedPath := append(currentPath, root)

	//DFS to find node
	for _, leaf := range node.Leaves {
		foundNode, path, _, found = findNodeAndPath(tree, leaf, target, updatedPath)
		if found {
			return foundNode, path, root, true
		}
	}

	return TreeNode{}, nil, "", false
}

func removeSubtree(accessMap *AccessMap, username string, parent string) {
	node, ok := accessMap.Tree[username]
	if !ok {
		return
	}
	for _, leaf := range node.Leaves {
		removeSubtree(accessMap, leaf, username)
	}
	delete(accessMap.Tree, username)
	if parent != "" {
		parentNode := accessMap.Tree[parent]
		newLeaves := []string{}
		for _, leaf := range parentNode.Leaves {
			if leaf != username {
				newLeaves = append(newLeaves, leaf)
			}
		}
		parentNode.Leaves = newLeaves
		accessMap.Tree[parent] = parentNode
	}
}

func updateSubtreeKeys(accessMap *AccessMap, parentSubtreeKey []byte, username string, version uint64) error {
	//using the parents key instedd of making a new one to match createinvite Struct
	subtreeKeyToWrap := parentSubtreeKey

	pubKey, ok := userlib.KeystoreGet(username + "_enc")
	if !ok {
		return errors.New("user public key not found")
	}

	wrappedKey, err := userlib.PKEEnc(pubKey, subtreeKeyToWrap)
	if err != nil {
		return err
	}

	node := accessMap.Tree[username]
	node.WrapKey = wrappedKey
	accessMap.Tree[username] = node
	for _, leaf := range node.Leaves {
		if err := updateSubtreeKeys(accessMap, subtreeKeyToWrap, leaf, version); err != nil {
			return err
		}
	}
	return nil
}

// used to make sure that the access path for a given file is valid
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// helper to rekey all the content so adversary cannot access it post revoke
func reEncContent(header *FileHeader, oldAESPair *AESPair, newAESPair *AESPair) error {
	type RapperMap struct {
		oldUUID uuid.UUID
		newUUID uuid.UUID
		wrapper SliceWrapper
	}

	var wrapperMappings []RapperMap

	currWrap := header.HeadChunkUUID
	for currWrap != uuid.Nil {
		encWrapper, ok := userlib.DatastoreGet(currWrap)
		if !ok {
			return errors.New("wrapper not found")
		}

		wrapperBytes, err := authDec(encWrapper, oldAESPair.EncKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt wrapper: %w", err)
		}

		var wrapper SliceWrapper
		if err := json.Unmarshal(wrapperBytes, &wrapper); err != nil {
			return fmt.Errorf("failed to unmarshal wrapper: %w", err)
		}

		encChunk, ok := userlib.DatastoreGet(wrapper.ContentUUID) //reenc chunk
		if !ok {
			return errors.New("content chunk not found")
		}
		chunkBytes, err := authDec(encChunk, oldAESPair.MacKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk: %w", err)
		}
		var chunk ContentChunk
		if err := json.Unmarshal(chunkBytes, &chunk); err != nil {
			return fmt.Errorf("failed to unmarshal chunk: %w", err)
		}

		if len(chunk.Content) < 64 {
			return errors.New("shorter than expected, fail")
		}
		oldTag := chunk.Content[:64]
		oldCipher := chunk.Content[64:]

		expectedOldTag, err := userlib.HMACEval(oldAESPair.MacKey, oldCipher) //double check integrity
		if err != nil {
			return fmt.Errorf("failed to compute old HMAC due to: %w", err)
		}
		if !userlib.HMACEqual(oldTag, expectedOldTag) {
			return errors.New("someone tampered with the content")
		}
		plaintext := userlib.SymDec(oldAESPair.EncKey, oldCipher)

		//now that we have the plaintext we can reenc with new key
		newCipherText := userlib.SymEnc(newAESPair.EncKey, userlib.RandomBytes(16), plaintext)
		newTag, err := userlib.HMACEval(newAESPair.MacKey, newCipherText)
		if err != nil {
			return fmt.Errorf("failed to compute new HMAC during re-encryption: %w", err)
		}

		//Chunk up the newly enc content & store it
		newChunk := ContentChunk{Content: append(newTag, newCipherText...)}
		newChunkBytes, err := json.Marshal(newChunk)
		if err != nil {
			return fmt.Errorf("failed to marshal new chunk during re-encryption: %w", err)
		}
		encNewChunk, err := authEnc(newChunkBytes, newAESPair.MacKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt new chunk during re-encryption: %w", err)
		}

		//hide newly enc chunk
		newUUID := uuid.New()
		userlib.DatastoreSet(newUUID, encNewChunk)
		userlib.DatastoreDelete(wrapper.ContentUUID) //delete old

		wrapper.ContentUUID = newUUID

		//store mapping for later
		newWrapperUUID := uuid.New()
		wrapperMappings = append(wrapperMappings, RapperMap{
			oldUUID: currWrap,
			newUUID: newWrapperUUID,
			wrapper: wrapper,
		})

		if currWrap == header.HeadChunkUUID {
			header.HeadChunkUUID = newWrapperUUID
		}
		if currWrap == header.TailChunkUUID {
			header.TailChunkUUID = newWrapperUUID
		}
		currWrap = wrapper.NextSlice
	}

	//lastly we have to update the pointers and store the new wrapper
	for i, mapping := range wrapperMappings {
		if mapping.wrapper.NextSlice != uuid.Nil {
			for _, nextMapping := range wrapperMappings {
				if nextMapping.oldUUID == mapping.wrapper.NextSlice {
					wrapperMappings[i].wrapper.NextSlice = nextMapping.newUUID //for new uuid access for next wrapper
					break
				}
			}
		}

		//have to store new wrapper with updated pointers for access
		newWrapperBytes, err := json.Marshal(wrapperMappings[i].wrapper)
		if err != nil {
			return fmt.Errorf("failed to marshal new wrapper during re-encryption: %w", err)
		}
		encNewwapper, err := authEnc(newWrapperBytes, newAESPair.EncKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt new wrapper during re-encryption: %w", err)
		}
		userlib.DatastoreSet(mapping.newUUID, encNewwapper)
		userlib.DatastoreDelete(mapping.oldUUID) //old wrapper
	}

	return nil
}
