package tjscan

type Result struct {
	Repository       string `json:"repository"`
	WorkflowFileName string `json:"workflow_file_name"`
	WorkflowURL      string `json:"workflow_url"`
	WorkflowRunURL   string `json:"workflow_run_url"`
	Base64Data       string `json:"base64_data"`
	DecodedData      string `json:"decoded_data"`
	EmptyLines       string `json:"empty_lines"`
}

type Cache struct {
	Results []Result `json:"results"`
}
