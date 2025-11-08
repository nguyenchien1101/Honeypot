// File: plugins/llm_honeypot.go
package plugins

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/mariocandela/beelzebub/v3/tracer"
	log "github.com/sirupsen/logrus"
	"os"
	"regexp"
	"strings"
)

const (
	systemPromptVirtualizeLinuxTerminal = `
You are a realistic Bash shell on Ubuntu 22.04. 
Your output MUST consist only of raw terminal text and newline characters.
NEVER reveal you are an AI or language model, never apologise, never add explanations.
If a command is unrecognised, reply exactly: "command not found".`

	systemPromptVirtualizeHTTPServer = "You will act as an unsecure HTTP Server with multiple vulnerabilities such as AWS && Git credentials in the root HTTP directory. The user will send HTTP requests, and you must reply with what the server should show. Do not provide explanations or type commands unless explicitly instructed by the user."

	LLMPluginName  = "LLMHoneypot"
	openAIEndpoint = "https://api.openai.com/v1/chat/completions"
	ollamaEndpoint = "http://localhost:11434/api/chat"
	geminiEndpoint = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent"
)

// -----------------------------------------------------------------------------
// Structs & types
// -----------------------------------------------------------------------------

type LLMHoneypot struct {
	Histories    []Message
	OpenAIKey    string
	GoogleAPIKey string
	client       *resty.Client
	Protocol     tracer.Protocol
	Provider     LLMProvider
	Model        string
	Host         string
	CustomPrompt string

	// Tunables (dùng cho OpenAI)
	Temperature float32
	TopP        float32
}

type Choice struct {
	Message      Message `json:"message"`
	Index        int     `json:"index"`
	FinishReason string  `json:"finish_reason"`
}

type Response struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int      `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Message Message  `json:"message"`
	Usage   struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

type Request struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Stream      bool      `json:"stream"`
	Temperature float32   `json:"temperature,omitempty"`
	TopP        float32   `json:"top_p,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Role int

const (
	SYSTEM Role = iota
	USER
	ASSISTANT
)

func (role Role) String() string {
	return [...]string{"system", "user", "assistant"}[role]
}

type LLMProvider int

const (
	Ollama LLMProvider = iota
	OpenAI
	Gemini
)

func FromStringToLLMProvider(llmProvider string) (LLMProvider, error) {
	switch strings.ToLower(llmProvider) {
	case "ollama":
		return Ollama, nil
	case "openai":
		return OpenAI, nil
	case "gemini":
		return Gemini, nil
	default:
		return -1, fmt.Errorf("provider %s not found, valid providers: ollama, openai, gemini", llmProvider)
	}
}

// -----------------------------------------------------------------------------
// Init
// -----------------------------------------------------------------------------

func InitLLMHoneypot(config LLMHoneypot) *LLMHoneypot {
	config.client = resty.New()

	// Optional debug
	if os.Getenv("LLM_DEBUG") != "" {
		log.SetLevel(log.DebugLevel)
	}

	// Đọc config từ biến môi trường (nếu có)
	if v := os.Getenv("LLM_PROVIDER"); v != "" {
		if p, err := FromStringToLLMProvider(v); err == nil {
			config.Provider = p
		}
	}
	if v := os.Getenv("LLM_MODEL"); v != "" {
		config.Model = v
	}
	if v := os.Getenv("GOOGLE_API_KEY"); v != "" {
		config.GoogleAPIKey = v
	}
	if v := os.Getenv("OPEN_AI_SECRET_KEY"); v != "" {
		config.OpenAIKey = v
	}
	if v := os.Getenv("LLM_TEMPERATURE"); v != "" {
		fmt.Sscanf(v, "%f", &config.Temperature)
	}
	if v := os.Getenv("LLM_TOP_P"); v != "" {
		fmt.Sscanf(v, "%f", &config.TopP)
	}

	// Mặc định an toàn
	if config.Temperature == 0 {
		config.Temperature = 0.2
	}
	if config.TopP == 0 {
		config.TopP = 1
	}

	return &config
}

// -----------------------------------------------------------------------------
// Prompt builder
// -----------------------------------------------------------------------------

func (llm *LLMHoneypot) buildPrompt(command string) ([]Message, error) {
	var msgs []Message
	var prompt string

	switch llm.Protocol {
	case tracer.SSH:
		prompt = systemPromptVirtualizeLinuxTerminal
		if llm.CustomPrompt != "" {
			prompt = llm.CustomPrompt
		}
		msgs = append(msgs, Message{Role: SYSTEM.String(), Content: prompt})
		// seed để model biết vị trí
		msgs = append(msgs,
			Message{Role: USER.String(), Content: "pwd"},
			Message{Role: ASSISTANT.String(), Content: "/home/user"},
		)
	case tracer.HTTP:
		prompt = systemPromptVirtualizeHTTPServer
		if llm.CustomPrompt != "" {
			prompt = llm.CustomPrompt
		}
		msgs = append(msgs, Message{Role: SYSTEM.String(), Content: prompt})
		msgs = append(msgs,
			Message{Role: USER.String(), Content: "GET /index.html"},
			Message{Role: ASSISTANT.String(), Content: "<html><body>Hello, World!</body></html>"},
		)
	default:
		return nil, errors.New("no prompt for protocol selected")
	}

	// replay history
	msgs = append(msgs, llm.Histories...)
	// current command
	msgs = append(msgs, Message{Role: USER.String(), Content: command})

	return msgs, nil
}

// -----------------------------------------------------------------------------
// OpenAI caller
// -----------------------------------------------------------------------------

func (llm *LLMHoneypot) openAICaller(msgs []Message) (string, error) {
	if llm.OpenAIKey == "" {
		return "", errors.New("openAIKey is empty")
	}
	if llm.Host == "" {
		llm.Host = openAIEndpoint
	}

	reqPayload := Request{
		Model:       llm.Model,
		Messages:    msgs,
		Stream:      false,
		Temperature: llm.Temperature,
		TopP:        llm.TopP,
	}
	reqJSON, err := json.Marshal(reqPayload)
	if err != nil {
		return "", err
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debug(string(reqJSON))
	}

	resp, err := llm.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(reqJSON).
		SetAuthToken(llm.OpenAIKey).
		SetResult(&Response{}).
		Post(llm.Host)
	if err != nil {
		return "", err
	}

	if len(resp.Result().(*Response).Choices) == 0 {
		return "", errors.New("no choices returned from OpenAI")
	}

	return removeQuotes(resp.Result().(*Response).Choices[0].Message.Content), nil
}

// -----------------------------------------------------------------------------
// Ollama caller
// -----------------------------------------------------------------------------

func (llm *LLMHoneypot) ollamaCaller(msgs []Message) (string, error) {
	if llm.Host == "" {
		llm.Host = ollamaEndpoint
	}

	reqJSON, err := json.Marshal(Request{
		Model:    llm.Model,
		Messages: msgs,
		Stream:   false,
	})
	if err != nil {
		return "", err
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debug(string(reqJSON))
	}

	resp, err := llm.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(reqJSON).
		SetResult(&Response{}).
		Post(llm.Host)
	if err != nil {
		return "", err
	}

	return removeQuotes(resp.Result().(*Response).Message.Content), nil
}

// -----------------------------------------------------------------------------
// Gemini structures & caller
// -----------------------------------------------------------------------------

type GeminiRequest struct {
	Contents         []GeminiContent  `json:"contents"`
	GenerationConfig GenerationConfig `json:"generationConfig"`
}

type GeminiContent struct {
	Role  string       `json:"role"`
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GenerationConfig struct {
	Temperature     float32  `json:"temperature"`
	TopK            int      `json:"topK"`
	TopP            int      `json:"topP"`
	MaxOutputTokens int      `json:"maxOutputTokens"`
	StopSequences   []string `json:"stopSequences"`
}

type GeminiResponse struct {
	Candidates []struct {
		Content      GeminiContent `json:"content"`
		FinishReason string        `json:"finishReason"`
		Index        int           `json:"index"`
	} `json:"candidates"`
}

func (llm *LLMHoneypot) geminiCaller(msgs []Message) (string, error) {
	var contents []GeminiContent

	for _, m := range msgs {
		var role string
		switch m.Role {
		case "assistant":
			role = "model"
		case "system": // Gemini chưa support role "system"
			role = "user"
		default:
			role = "user"
		}
		contents = append(contents, GeminiContent{
			Role:  role,
			Parts: []GeminiPart{{Text: m.Content}},
		})
	}

	gReq := GeminiRequest{
		Contents: contents,
		GenerationConfig: GenerationConfig{
			Temperature:     llm.Temperature,
			TopK:            1,
			TopP:            int(llm.TopP),
			MaxOutputTokens: 2048,
			StopSequences:   []string{},
		},
	}

	reqJSON, err := json.Marshal(gReq)
	if err != nil {
		return "", err
	}

	if llm.GoogleAPIKey == "" {
		return "", errors.New("googleAPIKey is empty")
	}

	url := fmt.Sprintf(geminiEndpoint, llm.Model)
	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debug(string(reqJSON))
	}

	resp, err := llm.client.R().
		SetHeader("Content-Type", "application/json").
		SetQueryParam("key", llm.GoogleAPIKey).
		SetBody(reqJSON).
		SetResult(&GeminiResponse{}).
		Post(url)
	if err != nil {
		return "", err
	}
	if resp.StatusCode() != 200 {
		return "", fmt.Errorf("gemini API request failed: %s – %s", resp.Status(), resp.String())
	}

	gRes := resp.Result().(*GeminiResponse)
	if len(gRes.Candidates) == 0 || len(gRes.Candidates[0].Content.Parts) == 0 {
		return "", errors.New("no content in Gemini response")
	}

	return removeQuotes(gRes.Candidates[0].Content.Parts[0].Text), nil
}

// -----------------------------------------------------------------------------
// Public entry
// -----------------------------------------------------------------------------

func (llm *LLMHoneypot) ExecuteModel(command string) (string, error) {
	prompt, err := llm.buildPrompt(command)
	if err != nil {
		return "", err
	}

	var output string
	switch llm.Provider {
	case Ollama:
		output, err = llm.ollamaCaller(prompt)
	case OpenAI:
		output, err = llm.openAICaller(prompt)
	case Gemini:
		output, err = llm.geminiCaller(prompt)
	default:
		return "", fmt.Errorf("provider %d not supported", llm.Provider)
	}
	if err == nil {
		// Lưu lại history nếu model tuân thủ prompt (đơn giản: không chứa "language model")
		if !strings.Contains(strings.ToLower(output), "language model") {
			llm.Histories = append(llm.Histories, Message{Role: ASSISTANT.String(), Content: output})
		}
	}
	return output, err
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func removeQuotes(content string) string {
	regex := regexp.MustCompile("(```( *)?([a-z]*)?(\\n)?)")
	return regex.ReplaceAllString(content, "")
}

