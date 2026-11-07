package host

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

// ProtocolVersion is bumped whenever a message or resource changes, so a
// controller can refuse an agent built from older code. Hello and Upgrade
// must never change shape, so any controller can upgrade any agent.
const ProtocolVersion = 11

// Hello is the first message an agent sends, and the first after it re-execs
// following an Upgrade.
type Hello struct {
	Proto int    `json:"proto"`
	Hash  string `json:"hash"`
	// Arch is the agent's GOARCH, so the controller knows which build to
	// compare against and upgrade to.
	Arch string `json:"arch"`
}

// Upgrade replaces the agent's binary and re-execs it. Nothing may be sent
// between Upgrade and the following Hello, or Error if the upgrade failed.
type Upgrade struct {
	Binary []byte `json:"binary"`
}

type FactsRequest struct{}

type FactsReply struct {
	Facts Facts `json:"facts"`
}

// Check asks the agent to check each resource in order, replying with one
// Checked per resource followed by Done.
type Check struct {
	Resources ResourceList `json:"resources"`
}

type Checked struct {
	ID      string `json:"id"`
	Status  Status `json:"status"`
	Diff    string `json:"diff,omitempty"`
	Warning string `json:"warning,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Apply applies the resources from the preceding Check, replying with one
// Applied per resource and handler followed by Done. Each resource or
// handler that's changed is announced with Applying first.
type Apply struct{}

type Applying struct {
	ID      string `json:"id"`
	Handler bool   `json:"handler,omitempty"`
}

type Applied struct {
	ID      string `json:"id"`
	Status  Status `json:"status"`
	Handler bool   `json:"handler,omitempty"`
	Diff    string `json:"diff,omitempty"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Prune asks the agent for the leftovers of the resources from the preceding
// Check, replying with one Leftovers per Pruner that has any or failed to
// list them, followed by Done.
type Prune struct{}

type Leftovers struct {
	ID    string   `json:"id"`
	Items []string `json:"items,omitempty"`
	Error string   `json:"error,omitempty"`
}

// Remove prunes one item that Leftovers listed, replying with Removed. The
// agent lists the resource's leftovers again first, and refuses an item
// that's no longer among them.
type Remove struct {
	ID   string `json:"id"`
	Item string `json:"item"`
}

type Removed struct {
	ID    string `json:"id"`
	Item  string `json:"item"`
	Error string `json:"error,omitempty"`
}

type Done struct {
	Failed bool `json:"failed"`
}

type Bye struct{}

type Status string

const (
	StatusInSync   Status = "in-sync"
	StatusDrifted  Status = "drifted"
	StatusDeferred Status = "deferred"
	StatusChanged  Status = "changed"
	StatusFailed   Status = "failed"
	StatusSkipped  Status = "skipped"
)

// Error reports a request the agent couldn't handle, such as a failed
// Upgrade, after which the old agent carries on.
type Error struct {
	Message string `json:"message"`
}

var messageTypes = registry(
	Hello{},
	Upgrade{},
	FactsRequest{},
	FactsReply{},
	Check{},
	Checked{},
	Apply{},
	Applying{},
	Applied{},
	Prune{},
	Leftovers{},
	Remove{},
	Removed{},
	Done{},
	Bye{},
	Error{},
)

// Conn exchanges protocol messages over a stream. It isn't safe for
// concurrent use in the same direction.
type Conn struct {
	enc *json.Encoder
	dec *json.Decoder
}

func NewConn(r io.Reader, w io.Writer) *Conn {
	return &Conn{enc: json.NewEncoder(w), dec: json.NewDecoder(r)}
}

// Send writes one message, which must be one of the message types above
// (not a pointer).
func (c *Conn) Send(msg any) error {
	body, err := marshalTagged(messageTypes, msg)
	if err != nil {
		return err
	}
	return c.enc.Encode(body)
}

// Receive reads one message, returning it as a value of its concrete type.
func (c *Conn) Receive() (any, error) {
	var raw tagged
	if err := c.dec.Decode(&raw); err != nil {
		return nil, err
	}
	return unmarshalTagged(messageTypes, raw)
}

type tagged struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body"`
}

func registry(values ...any) map[string]reflect.Type {
	types := make(map[string]reflect.Type, len(values))
	for _, v := range values {
		t := reflect.TypeOf(v)
		types[t.Name()] = t
	}
	return types
}

func marshalTagged(types map[string]reflect.Type, v any) (tagged, error) {
	t := reflect.TypeOf(v)
	if t == nil || types[t.Name()] != t {
		return tagged{}, fmt.Errorf("unregistered type %T", v)
	}
	body, err := json.Marshal(v)
	if err != nil {
		return tagged{}, err
	}
	return tagged{Type: t.Name(), Body: body}, nil
}

func unmarshalTagged(types map[string]reflect.Type, raw tagged) (any, error) {
	t, ok := types[raw.Type]
	if !ok {
		return nil, fmt.Errorf("unknown type %q", raw.Type)
	}
	ptr := reflect.New(t)
	if len(raw.Body) > 0 {
		if err := json.Unmarshal(raw.Body, ptr.Interface()); err != nil {
			return nil, fmt.Errorf("decoding %s: %w", raw.Type, err)
		}
	}
	return ptr.Elem().Interface(), nil
}

// ResourceList is a list of resources that survives a round trip through
// JSON, tagging each with its concrete type.
type ResourceList []Resource

func (l ResourceList) MarshalJSON() ([]byte, error) {
	out := make([]tagged, len(l))
	for i, r := range l {
		t, err := marshalTagged(resourceTypes, r)
		if err != nil {
			return nil, err
		}
		out[i] = t
	}
	return json.Marshal(out)
}

func (l *ResourceList) UnmarshalJSON(data []byte) error {
	var raw []tagged
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	out := make(ResourceList, len(raw))
	for i, t := range raw {
		v, err := unmarshalTagged(resourceTypes, t)
		if err != nil {
			return err
		}
		r, ok := v.(Resource)
		if !ok {
			return fmt.Errorf("%s isn't a resource", t.Type)
		}
		out[i] = r
	}
	*l = out
	return nil
}
