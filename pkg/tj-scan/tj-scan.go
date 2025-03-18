package tjscan

type Result struct {
	Repository       string `json:"repository"`
	WorkflowFileName string `json:"workflow_file_name"`
	WorkflowURL      string `json:"workflow_url"`
	WorkflowRunURL   string `json:"workflow_run_url"`
	Base64Data       string `json:"base64_data"`
	DecodedData      string `json:"decoded_data"`
	LineLinkOrNum    string `json:"line_link_or_number"`
}

type Cache struct {
	Results []Result `json:"results"`
}
