package chclient

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
	"log"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unsafe"
	"syscall"
	"encoding/binary"

	"github.com/kr/pty"
	"github.com/jpillora/backoff"
	"github.com/jpillora/chisel/share"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

type Config struct {
	shared      *chshare.Config
	Fingerprint string
	Auth        string
	KeepAlive   time.Duration
	Server      string
	Remotes     []string
}

type Client struct {
	*chshare.Logger
	config    *Config
	sshConfig *ssh.ClientConfig
	proxies   []*Proxy
	sshConn   ssh.Conn
	server    string
	running   bool
	runningc  chan error
}

func NewClient(config *Config) (*Client, error) {

	//apply default scheme
	if !strings.HasPrefix(config.Server, "http") {
		config.Server = "http://" + config.Server
	}

	u, err := url.Parse(config.Server)
	if err != nil {
		return nil, err
	}

	//apply default port
	if !regexp.MustCompile(`:\d+$`).MatchString(u.Host) {
		if u.Scheme == "https" || u.Scheme == "wss" {
			u.Host = u.Host + ":443"
		} else {
			u.Host = u.Host + ":80"
		}
	}

	//swap to websockets scheme
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)

	shared := &chshare.Config{}
	for _, s := range config.Remotes {
		r, err := chshare.DecodeRemote(s)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode remote '%s': %s", s, err)
		}
		shared.Remotes = append(shared.Remotes, r)
	}
	config.shared = shared

	client := &Client{
		Logger:   chshare.NewLogger("client"),
		config:   config,
		server:   u.String(),
		running:  true,
		runningc: make(chan error, 1),
	}

	user, pass := chshare.ParseAuth(config.Auth)

	client.sshConfig = &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		ClientVersion:   chshare.ProtocolVersion + "-client",
		HostKeyCallback: client.verifyServer,
	}

	return client, nil
}

//Start then Wait
func (c *Client) Run() error {
	go c.start()
	return c.Wait()
}

func (c *Client) verifyServer(hostname string, remote net.Addr, key ssh.PublicKey) error {
	expect := c.config.Fingerprint
	got := chshare.FingerprintKey(key)
	if expect != "" && !strings.HasPrefix(got, expect) {
		return fmt.Errorf("Invalid fingerprint (%s)", got)
	}
	//overwrite with complete fingerprint
	c.Infof("Fingerprint %s", got)
	return nil
}

//Starts the client
func (c *Client) Start() {
	go c.start()
}

func (c *Client) handle_shell() {
	sshConn := c.sshConn
	/*if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}*/

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	//connection, requests, err := newChannel.Accept()
	connection, requests, err := sshConn.OpenChannel("session", nil)
	if err != nil {
		log.Printf("Failed to open channel", err)
		return
	}

	// Fire up bash for this session
	log.Printf("exec bash!")
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
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

func (c *Client) start() {
	c.Infof("Connecting to %s\n", c.server)

	//prepare proxies
	for id, r := range c.config.shared.Remotes {
		proxy := NewProxy(c, id, r)
		go proxy.start()
		c.proxies = append(c.proxies, proxy)
	}

	//optional keepalive loop
	if c.config.KeepAlive > 0 {
		go func() {
			for range time.Tick(c.config.KeepAlive) {
				if c.sshConn != nil {
					c.sshConn.SendRequest("ping", true, nil)
				}
			}
		}()
	}

	//connection loop!
	var connerr error
	b := &backoff.Backoff{Max: 5 * time.Minute}

	for {
		if !c.running {
			break
		}
		if connerr != nil {
			d := b.Duration()
			c.Infof("Retrying in %s...\n", d)
			connerr = nil
			time.Sleep(d)
		}

		ws, err := websocket.Dial(c.server, chshare.ProtocolVersion, "http://localhost/")
		if err != nil {
			connerr = err
			continue
		}

		sshConn, chans, reqs, err := ssh.NewClientConn(ws, "", c.sshConfig)

		//NOTE: break == dont retry on handshake failures
		if err != nil {
			if strings.Contains(err.Error(), "unable to authenticate") {
				c.Infof("Authentication failed")
				c.Debugf(err.Error())
			} else {
				c.Infof(err.Error())
			}
			break
		}
		conf, _ := chshare.EncodeConfig(c.config.shared)
		c.Debugf("Sending configurating")
		t0 := time.Now()
		_, configerr, err := sshConn.SendRequest("config", true, conf)
		if err != nil {
			c.Infof("Config verification failed")
			break
		}
		if len(configerr) > 0 {
			c.Infof(string(configerr))
			break
		}
		c.Infof("Connected (Latency %s)", time.Now().Sub(t0))
		//connected
		b.Reset()

		c.sshConn = sshConn
		go ssh.DiscardRequests(reqs)
		shell := true
		if !shell {
			go chshare.RejectStreams(chans) //TODO allow client to ConnectStreams
		} else {
			c.Infof("Handle Shell")
			//for newchan := range chans {
				c.Infof("Shell Channel")
				go c.handle_shell()
			//}
		}
		err = sshConn.Wait()
		//disconnected
		c.sshConn = nil
		if err != nil && err != io.EOF {
			connerr = err
			c.Infof("Disconnection error: %s", err)
			continue
		}
		c.Infof("Disconnected\n")
	}
	close(c.runningc)
}

//Wait blocks while the client is running
func (c *Client) Wait() error {
	return <-c.runningc
}

//Close manual stops the client
func (c *Client) Close() error {
	c.running = false
	if c.sshConn == nil {
		return nil
	}
	return c.sshConn.Close()
}
// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

// Borrowed from https://github.com/creack/termios/blob/master/win/win.go
