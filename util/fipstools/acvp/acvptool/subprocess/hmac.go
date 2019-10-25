package subprocess

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// The following structures reflect the JSON of ACVP HMAC tests. See
// https://usnistgov.github.io/ACVP/artifacts/acvp_sub_mac.html#hmac_test_vectors

type hmacTestVectorSet struct {
	Groups []hmacTestGroup `json:"testGroups"`
}

type hmacTestGroup struct {
	ID     uint64 `json:"tgId"`
	Type   string `json:"testType"`
	MsgLen uint64 `json:"msgLen"`
	KeyLen uint32 `json:"keyLen"` // maximum possible value is 524288
	MACLen uint16 `json:"macLen"` // maximum possible value is 512
	Tests  []struct {
		ID     uint64 `json:"tcId"`
		KeyHex string `json:"key"`
		MsgHex string `json:"msg"`
	} `json:"tests"`
}

type hmacTestGroupResponse struct {
	ID    uint64             `json:"tgId"`
	Tests []hmacTestResponse `json:"tests"`
}

type hmacTestResponse struct {
	ID     uint64 `json:"tcId"`
	MACHex string `json:"mac,omitempty"`
}

// hmacPrimitive implements an ACVP algorithm by making requests to the
// subprocess to HMAC strings with the given key.
type hmacPrimitive struct {
	// algo is the ACVP name for this algorithm and also the command name
	// given to the subprocess to HMAC with this hash function.
	algo  string
	mdLen int // mdLen is the number of bytes of output that the underlying hash produces.
	m     *Subprocess
}

// hmac uses the subprocess to compute HMAC and returns the result.
func (h *hmacPrimitive) hmac(msg []byte, key []byte, outLen uint16) []byte {
	l := make([]byte, 2)
	binary.LittleEndian.PutUint16(l, outLen)
	result, err := h.m.transact(h.algo, 1, msg, key, l)
	if err != nil {
		panic("HMAC operation failed: " + err.Error())
	}
	return result[0]
}

func (h *hmacPrimitive) Process(vectorSet []byte) (interface{}, error) {
	var parsed hmacTestVectorSet
	if err := json.Unmarshal(vectorSet, &parsed); err != nil {
		return nil, err
	}

	var ret []hmacTestGroupResponse
	// See
	// https://usnistgov.github.io/ACVP/artifacts/acvp_sub_mac.html#hmac_test_vectors
	// for details about the tests.
	for _, group := range parsed.Groups {
		response := hmacTestGroupResponse{
			ID: group.ID,
		}
		if group.MACLen > uint16(h.mdLen)*8 {
			return nil, fmt.Errorf("test group %d specifies MAC length should be %d, but maximum possible length is %d", group.ID, group.MACLen, h.mdLen*8)
		}

		for _, test := range group.Tests {
			if uint64(len(test.MsgHex))*4 != group.MsgLen {
				return nil, fmt.Errorf("test case %d/%d contains hex message of length %d but specifies a bit length of %d", group.ID, test.ID, len(test.MsgHex), group.MsgLen)
			}
			msg, err := hex.DecodeString(test.MsgHex)
			if err != nil {
				return nil, fmt.Errorf("failed to decode hex in test case %d/%d: %s", group.ID, test.ID, err)
			}

			if uint32(len(test.KeyHex))*4 != group.KeyLen {
				return nil, fmt.Errorf("test case %d/%d contains hex key of length %d but specifies a bit length of %d", group.ID, test.ID, len(test.KeyHex), group.KeyLen)
			}
			key, err := hex.DecodeString(test.KeyHex)
			if err != nil {
				return nil, fmt.Errorf("failed to decode key in test case %d/%d: %s", group.ID, test.ID, err)
			}

			// https://usnistgov.github.io/ACVP/artifacts/acvp_sub_mac.html#hmac_vector_responses
			response.Tests = append(response.Tests, hmacTestResponse{
				ID:     test.ID,
				MACHex: hex.EncodeToString(h.hmac(msg, key, group.MACLen)),
			})
		}

		ret = append(ret, response)
	}

	return ret, nil
}
