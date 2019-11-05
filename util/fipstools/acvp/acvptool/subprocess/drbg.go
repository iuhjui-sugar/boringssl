package subprocess

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// The following structures reflect the JSON of ACVP DRBG tests. See
// https://usnistgov.github.io/ACVP/artifacts/acvp_sub_drbg.html#rfc.section.4

type drbgTestVectorSet struct {
	Groups []drbgTestGroup `json:"testGroups"`
}

type drbgTestGroup struct {
	ID        uint64 `json:"tgId"`
	Mode      string `json:"mode"`
	DerFunc   bool   `json:"derFunc,omitempty"`
	PredRes   bool   `json:"predResistance"`
	ReSeed    bool   `json:"reSeed"`
	EntBits   uint64 `json:"entropyInputLen"`
	NonceBits uint64 `json:"nonceLen"`
	PersoBits uint64 `json:"persoStringLen"`
	AddtlBits uint64 `json:"additionalInputLen"`
	RetBits   uint64 `json:"returnedBitsLen"`
	Tests     []struct {
		ID       uint64 `json:"tcId"`
		EntHex   string `json:"entropyInput"`
		NonceHex string `json:"nonce"`
		PersoHex string `json:"persoString"`
		Other    []struct {
			AddtlHex string `json:"additionalInput"`
			EntHex   string `json:"entropyInput"`
			Use      string `json:"intendedUse"`
		} `json:"otherInput"`
	} `json:"tests"`
}

type drbgTestGroupResponse struct {
	ID    uint64             `json:"tgId"`
	Tests []drbgTestResponse `json:"tests"`
}

type drbgTestResponse struct {
	ID     uint64 `json:"tcId"`
	OutHex string `json:"returnedBits,omitempty"`
}

// params needed to generate drbg bits through subprocess
type drbgParams struct {
	op      string
	ent     []byte
	nonce   []byte
	perso   []byte
	addtl   [][]byte
	outBits uint64
}

// drbg implements an ACVP algorithm by making requests to the
// subprocess to generate random bits with the given entropy and other paramaters.
type drbg struct {
	// algo is the ACVP name for this algorithm and also the command name
	// given to the subprocess to generate random bytes.
	algo  string
	modes map[string]bool // the supported underlying primitives for the DRBG
	m     *Subprocess
}

// DRBG uses the subprocess to compute random bits and returns the result.
func (d *drbg) generate(p *drbgParams) []byte {
	if p.outBits%8 != 0 {
		panic("fractional-byte output length requested: " + strconv.FormatUint(p.outBits, 10))
	}
	outBytes := p.outBits / 8
	var result [][]byte
	var err error
	if len(p.nonce) == 0 {
		result, err = d.m.transact(p.op, 1, p.ent, p.perso, p.addtl[0], p.addtl[1])
	} else {
		result, err = d.m.transact(p.op, 1, p.ent, p.perso, p.addtl[0], p.addtl[1], p.nonce)
	}
	if err != nil {
		panic("DRBG operation failed: " + err.Error())
	}
	if l := uint64(len(result[0])); l < outBytes {
		panic(fmt.Sprintf("DRBG result too short: %d bytes but wanted %d", l, outBytes))
	}
	return result[0][:outBytes]
}

func (d *drbg) Process(vectorSet []byte) (interface{}, error) {
	var parsed drbgTestVectorSet
	if err := json.Unmarshal(vectorSet, &parsed); err != nil {
		return nil, err
	}

	var ret []drbgTestGroupResponse
	// See
	// https://usnistgov.github.io/ACVP/artifacts/acvp_sub_drbg.html#rfc.section.4
	// for details about the tests.
	for _, group := range parsed.Groups {
		response := drbgTestGroupResponse{
			ID: group.ID,
		}

		if _, ok := d.modes[group.Mode]; !ok {
			return nil, fmt.Errorf("test group %d specifies %s mode, which is not supported for the %s algorithm", group.ID, group.Mode, d.algo)
		}

		if group.PredRes {
			return nil, fmt.Errorf("Test group %d specifies prediction resistance enabled which is not supported", group.ID)
		}

		if group.ReSeed {
			return nil, fmt.Errorf("Test group %d specifies re-seeding enabled which is not supported", group.ID)
		}

		for _, test := range group.Tests {
			ent, err := extractField(test.EntHex, group.EntBits)
			if err != nil {
				return nil, fmt.Errorf("failed to extract entropy hex from test case %d/%d: %s", group.ID, test.ID, err)
			}

			nonce, err := extractField(test.NonceHex, group.NonceBits)
			if err != nil {
				return nil, fmt.Errorf("failed to extract nonce hex from test case %d/%d: %s", group.ID, test.ID, err)
			}

			perso, err := extractField(test.PersoHex, group.PersoBits)
			if err != nil {
				return nil, fmt.Errorf("failed to extract personalization hex from test case %d/%d: %s", group.ID, test.ID, err)
			}

			if len(test.Other) != 2 {
				return nil, fmt.Errorf("test case %d/%d provides %d additional inputs, but subprocess only expects %d", group.ID, test.ID, len(test.Other), 2)
			}

			var p = drbgParams{op: d.algo + "/" + group.Mode, outBits: group.RetBits, ent: ent, nonce: nonce, perso: perso}

			for _, other := range test.Other {
				addtl, err := extractField(other.AddtlHex, group.AddtlBits)
				p.addtl = append(p.addtl, addtl)
				if err != nil {
					return nil, fmt.Errorf("failed to extract additional input hex from test case %d/%d: %s", group.ID, test.ID, err)
				}
			}

			// https://usnistgov.github.io/ACVP/artifacts/acvp_sub_drbg.html#rfc.section.4
			response.Tests = append(response.Tests, drbgTestResponse{
				ID:     test.ID,
				OutHex: hex.EncodeToString(d.generate(&p)),
			})
		}

		ret = append(ret, response)
	}

	return ret, nil
}

// validate the length and hex of a JSON field in test vectors
func extractField(fieldHex string, bits uint64) ([]byte, error) {
	if uint64(len(fieldHex)*4) != bits {
		return nil, fmt.Errorf("expected %d bits but have %d long hex string", bits, len(fieldHex))
	}
	return hex.DecodeString(fieldHex)
}
