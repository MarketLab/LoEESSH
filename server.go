// A small SSH daemon providing bash sessions
//
// Server:
// cd my/new/dir/
// #generate server keypair
// ssh-keygen -t rsa
// go get -v .
// go run sshd.go
//
// Client:
// ssh foo@localhost -p 2200 #pass=bar

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

type rsshtKey struct {
	machID string
}

type rsshtSession struct {
	machID       string
	sshConn      *ssh.ServerConn
	httpListener net.Listener
	quit         chan bool
}

var authorizedKeys map[string]rsshtKey

func acceptAndForward(listener net.Listener, session *rsshtSession, sshReq *forwardedTCPIPRequest) {
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			select {
			case <-session.quit:
				return
			default:
				log.Printf("Failed to accept incoming connection (%s)", err)
				continue
			}
		}

		sshc, reqs, err := session.sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(sshReq))
		if err != nil {
			log.Printf("Failed to open ssh channel: %s for: %s \n" err, sshReq)
			continue
		}

		go ssh.DiscardRequests(reqs)

		close := func() {
			sshc.Close()
			tcpConn.Close()
			log.Printf("Session closed")
		}

		var once sync.Once
		go func() {
			io.Copy(tcpConn, sshc)
			once.Do(close)
		}()
		go func() {
			io.Copy(sshc, tcpConn)
			once.Do(close)
		}()
	}
}

var unixSocketsDir string

func createSession(sshConn *ssh.ServerConn) (s *rsshtSession) {
	opts := authorizedKeys[sshConn.Permissions.Extensions["key"]]
	session := rsshtSession{machID: opts.machID, sshConn: sshConn, quit: make(chan bool)}
	sockname := unixSocketsDir + "/" + opts.machID
	os.Remove(sockname)
	listener, err := net.Listen("unix", sockname)
	if err != nil {
		log.Printf("Failed to create session: %s", err.Error())
		return nil
	}
	session.httpListener = listener

	go acceptAndForward(session.httpListener, &session, &forwardedTCPIPRequest{"localhost", 80, "proxy", 0})

	return &session
}

func (s *rsshtSession) Close() {
	close(s.quit)
	s.httpListener.Close()
	s.sshConn.Close()
}

var authorizedKeysPath string
var hostKeyPath string
var authMutex sync.RWMutex

func observeAuthKeysFile() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to initialize authorized keys observer: %s", err.Error())
	}
	if err := watcher.Add(authorizedKeysPath); err != nil {
		return fmt.Errorf("failed to initialize authorized keys observer: %s", err.Error())
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("failed to process event queue from authorized keys observer")
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Println("detected change in authorized keys file - reloading")

				authMutex.Lock()
				authorizedKeys = loadAuthorizedKeys(authorizedKeysPath)
				authMutex.Unlock()
			}
			if event.Op&fsnotify.Remove == fsnotify.Remove {
				log.Println("detected change in authorized keys file - reloading")

				authMutex.Lock()
				authorizedKeys = loadAuthorizedKeys(authorizedKeysPath)
				authMutex.Unlock()
			}
		}
	}

	return nil
}

func main() {
	var found = false

	if authorizedKeysPath, found = os.LookupEnv("AUTHORIZED_KEYS_PATH"); !found {
		authorizedKeysPath = "/keys/authorized_keys"
	}

	authMutex.Lock()
	authorizedKeys = loadAuthorizedKeys(authorizedKeysPath)
	authMutex.Unlock()

	go observeAuthKeysFile()

	if hostKeyPath, found = os.LookupEnv("HOST_KEY_PATH"); !found {
		hostKeyPath = "/keys/host_key"
	}
	hostKey := loadHostKey(hostKeyPath)

	if unixSocketsDir, found = os.LookupEnv("UNIX_SOCKETS_DIR"); !found {
		unixSocketsDir = "/sockets"
	}
	os.MkdirAll(unixSocketsDir, 0700)

	rsshtSessions := map[string]*rsshtSession{}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			log.Println(c.RemoteAddr(), "authenticate with", key.Type(), strconv.Quote(string(key.Marshal())))
			keyString := string(key.Marshal())
			authMutex.RLock()
			defer authMutex.RUnlock()
			if _, found := authorizedKeys[keyString]; found {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"key": keyString,
					},
				}, nil
			}
			return nil, fmt.Errorf("key rejected for %q", c.User())
		},
	}
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}

	// Accept all connections
	log.Print("Listening on 2200...")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}

		tcpConn.SetDeadline(time.Now().Add(10 * time.Second))

		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		tcpConn.SetDeadline(time.Time{})

		key := sshConn.Permissions.Extensions["key"]
		oldSession, found := rsshtSessions[key]
		if found {
			log.Printf("Cleaning up old session for key: %s (%s, %s)",
				strconv.Quote(key), oldSession.sshConn.RemoteAddr(), oldSession.sshConn.ClientVersion())
			oldSession.Close()
		}
		rsshtSessions[key] = createSession(sshConn)

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

		go func(in <-chan *ssh.Request) {
			for req := range in {
				log.Println("OOB Request:", req.Type, "wants reply:", req.WantReply, "payload:", strconv.Quote(string(req.Payload)))
				switch req.Type {
				case "tcpip-forward":
					req.Reply(true, nil)
					opts := tcpIPForwardRequest{}
					ssh.Unmarshal(req.Payload, &opts)
					log.Println("forward:", opts)
				case "keepalive@openssh.com":
					req.Reply(true, nil)
				default:
					req.Reply(false, []byte("unknown request"))
				}
			}
		}(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func loadAuthorizedKeys(fname string) map[string]rsshtKey {
	keys := map[string]rsshtKey{}

	bytes, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatal("Failed to load authorized keys from:", fname)
	}

	var count = 0
	for len(bytes) > 0 {
		key, _, options, rest, err := ssh.ParseAuthorizedKey(bytes)
		if err != nil {
			log.Printf("failed to parse authorized keys at: %s", strconv.Quote(string(bytes[:30])))
			bytes = rest

			continue
		}
		count++
		keyString := string(key.Marshal())
		rsshtkey := rsshtKey{}
		for _, option := range options {
			if val, found := withoutPrefix(option, "machid="); found {
				rsshtkey.machID = val
			}
		}
		keys[keyString] = rsshtkey
		bytes = rest
	}
	log.Printf("loaded %d keys from %s", count, fname)

	return keys
}

func loadHostKey(fname string) ssh.Signer {
	privateBytes, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatal("Failed to load private key (./ssh_host_rsa_key)")
	}
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}
	return private
}

func withoutPrefix(str string, prefix string) (string, bool) {
	if strings.HasPrefix(str, prefix) {
		return str[len(prefix):], true
	}
	return "", false
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" && t != "direct-tcpip" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}
	log.Println("accepting channel:", newChannel.ChannelType(), "with payload:", strconv.Quote(string(newChannel.ExtraData())))

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Fire up bash for this session
	bash := exec.Command("bash")

	// Prepare teardown function
	close := func() {
		connection.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			log.Printf("Failed to exit bash (%s)", err)
		}
		log.Printf("Session closed")
	}

	// Allocate a terminal for this channel
	log.Print("Creating pty...")
	bashf, err := pty.Start(bash)
	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		close()
		return
	}

	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			}
		}
	}()
}

// SSH protocol frames
type tcpIPForwardRequest struct {
	Address string
	Port    uint32
}

type forwardedTCPIPRequest struct {
	Address    string
	Port       uint32
	SrcAddress string
	SrcPort    uint32
}
