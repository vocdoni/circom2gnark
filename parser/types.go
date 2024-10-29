package parser

// SnarkJSProof represents the proof structure output by SnarkJS.
type SnarkJSProof struct {
	PiA      []string   `json:"pi_a"`
	PiB      [][]string `json:"pi_b"`
	PiC      []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
}

// SnarkJSVerificationKey represents the verification key structure output by SnarkJS.
type SnarkJSVerificationKey struct {
	Protocol      string       `json:"protocol"`
	Curve         string       `json:"curve"`
	NPublic       int          `json:"nPublic"`
	VkAlpha1      []string     `json:"vk_alpha_1"`
	VkBeta2       [][]string   `json:"vk_beta_2"`
	VkGamma2      [][]string   `json:"vk_gamma_2"`
	VkDelta2      [][]string   `json:"vk_delta_2"`
	IC            [][]string   `json:"IC"`
	VkAlphabeta12 [][][]string `json:"vk_alphabeta_12"` // Not used in verification
}
