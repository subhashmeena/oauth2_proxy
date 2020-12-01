package providers

import (
        "encoding/base64"
        "fmt"
        "github.com/bitly/oauth2_proxy/cookie"
        "strconv"
        "strings"
        "github.com/pierrec/lz4"
        "time"
        "bytes"
        "io"
        "io/ioutil"
        "crypto/md5"
        "encoding/hex"
)


type SessionState struct {
        AccessToken  string
        IDToken      string
        ExpiresOn    time.Time
        RefreshToken string
        Email        string
        User         string
        ID           string
        Groups       string
}

func (s *SessionState) IsExpired() bool {
        if !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
                return true
        }
        return false
}

func (s *SessionState) String() string {
        o := fmt.Sprintf("Session{%s", s.accountInfo())
        if s.AccessToken != "" {
                o += " token:true"
        }
        if !s.ExpiresOn.IsZero() {
                o += fmt.Sprintf(" expires:%s", s.ExpiresOn)
        }
        if s.RefreshToken != "" {
                o += " refresh_token:true"
        }
        if s.Groups != "" {
                o += fmt.Sprintf(" groups:%s", s.Groups)
        }
        return o + "}"
}

func (s *SessionState) EncodeSessionState(c *cookie.Cipher) (string, error) {

        if c == nil || s.AccessToken == "" {
                return s.accountInfo(), nil
        }
		return s.EncryptedString(c)
		
                // packed, err := msgpack.Marshal(s)
                // packed,err := json.Marshal(s)
		// if err != nil {
		// 	return nil, fmt.Errorf("error marshalling session state to msgpack: %w", err)
		// }

		// // if !compress {
		// // 	return c.Encrypt(packed)
		// // }

		// compressed, err := lz4Compress(packed)
		// if err != nil {
		// 	return nil, err
		// }
                // return c.Encrypt(compressed)
                //marshal
                //compress
                //encrypt
                //decrypt
                //uncompress
                //unmarshal
}

func (s *SessionState) accountInfo() string {
        return fmt.Sprintf("email:%s user:%s id:%s", s.Email, s.User, s.ID)
}

func (s *SessionState) EncryptedString(c *cookie.Cipher) (string, error) {
        var err error
        if c == nil {
                panic("error. missing cipher")
        }
        a := s.AccessToken


        if a != "" {
                // fmt.Println("Access token before hashing is : ",a);
                // b,compressionError := lz4Compress([]byte(a))
                // if compressionError != nil {
                //         fmt.Print("Compression error occured",compressionError);
                // }
                
                
                d, _ := GetMD5Hash(a)
                // fmt.Println("Access token after hashing and before encryption  is : ",d);

                // fmt.Println("Access token after compression is : ",d);
                if a, err = c.Encrypt(d); err != nil {
                        return "", err
                }
                // fmt.Println("Access token after encryption is ",a);
        }
        r := s.RefreshToken
        if r != "" {
                if r, err = c.Encrypt(r); err != nil {
                        return "", err
                }
        }

        encoded_groups := base64.StdEncoding.EncodeToString([]byte(s.Groups))

        return fmt.Sprintf("%s|%s|%d|%s|%s", s.accountInfo(), a, s.ExpiresOn.Unix(), r, encoded_groups), nil
}

func decodeSessionStatePlain(v string) (s *SessionState, err error) {
        chunks := strings.Split(v, " ")
        if len(chunks) != 3 {
                return nil, fmt.Errorf("could not decode session state: expected 3 chunks got %d", len(chunks))
        }

        email := strings.TrimPrefix(chunks[0], "email:")
        user := strings.TrimPrefix(chunks[1], "user:")
        uid := strings.TrimPrefix(chunks[2], "id:")
        if user == "" {
                user = strings.Split(email, "@")[0]
        }

        return &SessionState{User: user, Email: email, ID: uid}, nil
}

func decodeUserGroups(v string) (groups string, err error) {
        decoded_groups, err := base64.StdEncoding.DecodeString(v)
        if err != nil {
                return "", err
        }
        return string(decoded_groups), nil
}

func DecodeSessionState(v string, c *cookie.Cipher) (s *SessionState, err error) {



        if c == nil {
                return decodeSessionStatePlain(v)
        }

        chunks := strings.Split(v, "|")
        if len(chunks) != 5 {
                err = fmt.Errorf("invalid number of fields (got %d expected 5)", len(chunks))
                return
        }

        sessionState, err := decodeSessionStatePlain(chunks[0])
        if err != nil {
                return nil, err
        }

        
        // Access Token
        if chunks[1] != "" {
             
                // fmt.Println("Access token before Decrypting is : ",chunks[1]);
                decryptedValue,decryptionError := c.Decrypt(chunks[1]); //erro handling remains
                if decryptionError != nil {
                        fmt.Print("Decryption error occured",decryptionError);
                }
                
                // decompressedBytes, decompressionError := lz4Decompress([]byte(decryptedValue))

                // if decompressionError != nil {
                //         fmt.Print("Decompression error occured",decompressionError);
                // }


                sessionState.AccessToken = string(decryptedValue)
                // if sessionState.AccessToken, err = string(lz4Decompress([]byte(c.Decrypt(chunks[1])))); err != nil {
                //         return nil, err
                // }
                // fmt.Println("Access token after decompressing is : ",sessionState.AccessToken)
        }

        ts, _ := strconv.Atoi(chunks[2])
        sessionState.ExpiresOn = time.Unix(int64(ts), 0)

        // Refresh Token
        if chunks[3] != "" {
                if sessionState.RefreshToken, err = c.Decrypt(chunks[3]); err != nil {
                        return nil, err
                }
        }

        // User groups
        if chunks[4] != "" {
                if sessionState.Groups, err = decodeUserGroups(chunks[4]); err != nil {
                        return nil, err
                }
        }

        return sessionState, nil



		
	// 	fmt.Println("Encrypted state in DecodeSessionState()  is : ",v);
	// 	decrypted, err := c.Decrypt(v)
	// 	fmt.Println("Decrypted state in DecodeSessionState()  is : ",decrypted);

	// 	if c == nil {
        //         return decodeSessionStatePlain(v)
	// 	}
		
	// 	packed, err = lz4Decompress(decrypted)
	// 	if err != nil {
	// 		return nil, err
	// 	}

        //         fmt.Println("Decompressed authentication token is : ",packed);
        //         var ss SessionState
        //         err = json.Unmarshal(packed, &ss)
        //         if err != nil {
        //                 return nil, fmt.Errorf("error unmarshalling data to session state: %w", err)
        //         }
		
        // chunks := strings.Split(packed, "|")
        // if len(chunks) != 5 {
        //         err = fmt.Errorf("invalid number of fields (got %d expected 5)", len(chunks))
        //         return
        // }

        // sessionState, err := decodeSessionStatePlain(chunks[0])
        // if err != nil {
        //         return nil, err
        // }

        // // Access Token
        // if chunks[1] != "" {
        //         if sessionState.AccessToken, err = c.Decrypt(chunks[1]); err != nil {
        //                 return nil, err
        //         }
        // }

        // ts, _ := strconv.Atoi(chunks[2])
        // sessionState.ExpiresOn = time.Unix(int64(ts), 0)

        // // Refresh Token
        // if chunks[3] != "" {
        //         if sessionState.RefreshToken, err = c.Decrypt(chunks[3]); err != nil {
        //                 return nil, err
        //         }
        // }

        // // User groups
        // if chunks[4] != "" {
        //         if sessionState.Groups, err = decodeUserGroups(chunks[4]); err != nil {
        //                 return nil, err
        //         }
        // }

        // return sessionState, nil
}
func lz4Compress(payload []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	zw := lz4.NewWriter(nil)
	zw.Header = lz4.Header{
		BlockMaxSize:     65536,
		CompressionLevel: 12,
	}
	zw.Reset(buf)

	reader := bytes.NewReader(payload)
	_, err := io.Copy(zw, reader)
	if err != nil {
		return nil, fmt.Errorf("error copying lz4 stream to buffer: %w", err)
	}
	err = zw.Close()
	if err != nil {
		return nil, fmt.Errorf("error closing lz4 writer: %w", err)
	}

	compressed, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading lz4 buffer: %w", err)
	}

	return compressed, nil
}
func GetMD5Hash(value string)(string,error){
        name := value;
	s := "brave warrior cat "
	h := md5.New()
	io.WriteString(h,s+name)
	return hex.EncodeToString(h.Sum(nil)),nil;
}

func lz4Decompress(compressed []byte) ([]byte, error) {
	reader := bytes.NewReader(compressed)
	buf := new(bytes.Buffer)
	zr := lz4.NewReader(nil)
	zr.Reset(reader)
	_, err := io.Copy(buf, zr)
	if err != nil {
		return nil, fmt.Errorf("error copying lz4 stream to buffer: %w", err)
	}

	payload, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading lz4 buffer: %w", err)
	}

	return payload, nil
}
