package custom

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/Perruer/sapper/cmd/helpers"
	apiv1 "github.com/Perruer/sapper/gen/api/v1"
	"github.com/Perruer/sapper/gen/api/v1/apiv1connect"
	"github.com/sashabaranov/go-openai"
	"github.com/spf13/cobra"
)

const PROMPT_TEMPLATE = `You are an AI assistant that helps users understand and work with a DSL (Domain Specific Language) for querying a graph database of supply chain security artifacts. You have access to documentation and examples about this DSL through the provided context.

If the user asks for a DSL query, convert their natural language into the appropriate DSL script. The DSL uses keywords like: dependencies, dependents, library, vuln, xor, or, and.

If the user asks general questions about the DSL or how it works, provide helpful explanations based on the context.

YOU CAN ONLY OUTPUT THE DSL QUERY. NO REGULAR LANGUAGE.

You cannot output periods, commas, or other punctuation.

If an '@' is used in a package name, even if a version is not included, leave it in and do not remove it.

If a user asks for vulnerablities for a package they mean dependencies of type vuln, for a query, and if we want to know what a vuln affects, dependents of type library.

Globsearch queries can be used to find anything that might exist in a node, not only names of nodes, so for types of packages, if it is inside of a purl you can find it, versions, ecosystem, etc. For vulns you can do globsearches like '*GHSA*', '*CVE*', etc, depending on what the user asks.

Try to surrond a globsearch pattern with as much glob as you can, be as general as possible.


If this is a leaderboard query, you should prefix your answer with 'leaderboard:'.
If this is a regular query, you should prefix your answer with 'query:'.
If this is a globsearch query, you should prefix your answer with 'globsearch:'.


Documentation of the DSL:

%s`

// options holds the command-line options.
type options struct {
	maxOutput                int
	showInfo                 bool
	saveQuery                string
	addr                     string
	output                   string
	queryServiceClient       apiv1connect.QueryServiceClient
	leaderboardServiceClient apiv1connect.LeaderboardServiceClient
	graphServiceClient       apiv1connect.GraphServiceClient
	model                    string
	baseURL                  string
}

// AddFlags adds command-line flags to the provided cobra command.
func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&o.maxOutput, "max-output", 10, "maximum number of results to display")
	cmd.Flags().BoolVar(&o.showInfo, "show-info", true, "display the info column")
	cmd.Flags().StringVar(&o.addr, "addr", "http://localhost:8089", "address of the Sapper server")
	cmd.Flags().StringVar(&o.model, "model", envOr("SAPPER_LLM_MODEL", "gpt-4o-mini"), "chat model to use (env SAPPER_LLM_MODEL)")
	cmd.Flags().StringVar(&o.baseURL, "base-url", os.Getenv("SAPPER_LLM_BASE_URL"),
		"OpenAI-compatible API address, e.g. http://localhost:11434/v1 for Ollama (env SAPPER_LLM_BASE_URL; default: OpenAI)")
	cmd.Flags().StringVar(&o.output, "output", "table", "output format (table or json)")
}

// Run executes the custom command with the provided arguments.
func (o *options) Run(cmd *cobra.Command, args []string) error {

	// Any OpenAI-compatible chat API works. A key is needed for OpenAI itself; local servers such as
	// Ollama usually accept any value.
	apiKey := envOr("SAPPER_LLM_API_KEY", os.Getenv("OPENAI_API_KEY"))
	if apiKey == "" && o.baseURL == "" {
		return fmt.Errorf("set SAPPER_LLM_API_KEY (or OPENAI_API_KEY), or point --base-url at a local OpenAI-compatible server")
	}
	config := openai.DefaultConfig(apiKey)
	if o.baseURL != "" {
		config.BaseURL = strings.TrimRight(o.baseURL, "/")
	}
	client := openai.NewClientWithConfig(config)

	// The documentation of the query language goes into the system prompt as a whole.
	messages := []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleSystem,
			Content: fmt.Sprintf(PROMPT_TEMPLATE, strings.Join(knowledge, "\n\n")),
		},
	}

	// Initialize client if not injected (for testing)
	if o.queryServiceClient == nil {
		o.queryServiceClient = apiv1connect.NewQueryServiceClient(
			http.DefaultClient,
			o.addr,
			connect.WithGRPC(),
			connect.WithSendGzip(),
		)
	}

	if o.leaderboardServiceClient == nil {
		o.leaderboardServiceClient = apiv1connect.NewLeaderboardServiceClient(
			http.DefaultClient,
			o.addr,
		)
	}

	if o.graphServiceClient == nil {
		o.graphServiceClient = apiv1connect.NewGraphServiceClient(
			http.DefaultClient,
			o.addr,
		)
	}

	fmt.Println("Starting chat session. Type 'exit' to end.")

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\nYou: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading input: %w", err)
		}

		input = strings.TrimSpace(input)
		if strings.ToLower(input) == "exit" {
			fmt.Println("Ending chat session. Goodbye!")
			return nil
		}

		// Add user's message
		messages = append(messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleUser,
			Content: input,
		})

		resp, err := client.CreateChatCompletion(
			context.Background(),
			openai.ChatCompletionRequest{
				Model:    o.model,
				Messages: messages,
			},
		)
		if err != nil {
			return fmt.Errorf("failed to create chat completion: %w", err)
		}

		if len(resp.Choices) == 0 {
			return fmt.Errorf("the model returned no answer")
		}
		script := resp.Choices[0].Message.Content
		messages = append(messages, openai.ChatCompletionMessage{Role: openai.ChatMessageRoleAssistant, Content: script})

		// Execute the query and capture output
		var queryResult string
		if strings.TrimSpace(script) != "" {
			var buf strings.Builder

			// Check if this is a leaderboard query
			if strings.HasPrefix(strings.TrimSpace(script), "leaderboard:") {

				// Remove the "leaderboard:" prefix
				cleanScript := strings.TrimPrefix(strings.TrimSpace(script), "leaderboard:")
				fmt.Printf("\nAssistant: I'll help you with that. I'm going to use this leaderboard query:\n\"%s\"\n", cleanScript)

				req := connect.NewRequest(&apiv1.CustomLeaderboardRequest{Script: cleanScript})
				res, err := o.leaderboardServiceClient.CustomLeaderboard(cmd.Context(), req)

				if err != nil {
					queryResult = fmt.Sprintf("Leaderboard query failed: %v", err)
				} else if len(res.Msg.Queries) == 0 {
					queryResult = "No results found"
				} else {
					switch o.output {
					case "json":
						jsonOutput, err := helpers.FormatCustomQueriesJSON(res.Msg.Queries)
						if err != nil {
							queryResult = fmt.Sprintf("Failed to format JSON: %v", err)
						} else {
							queryResult = string(jsonOutput)
						}
					case "table":
						err = formatLeaderboardTable(&buf, res.Msg.Queries, o.maxOutput, o.showInfo)
						if err != nil {
							queryResult = fmt.Sprintf("Failed to format table: %v", err)
						} else {
							queryResult = buf.String()
						}
					}
				}
			} else if strings.HasPrefix(strings.TrimSpace(script), "query:") {
				// Remove the "query:" prefix
				cleanScript := strings.TrimPrefix(strings.TrimSpace(script), "query:")
				fmt.Printf("\nAssistant: I'll help you with that. I'm going to use this query:\n\"%s\"\n", cleanScript)

				req := connect.NewRequest(&apiv1.QueryRequest{Script: cleanScript})
				res, err := o.queryServiceClient.Query(cmd.Context(), req)

				if err != nil {
					queryResult = fmt.Sprintf("Query failed: %v", err)
				} else if len(res.Msg.Nodes) == 0 {
					queryResult = "No results found"
				} else {
					switch o.output {
					case "json":
						jsonOutput, err := helpers.FormatNodeJSON(res.Msg.Nodes)
						if err != nil {
							queryResult = fmt.Sprintf("Failed to format JSON: %v", err)
						} else {
							queryResult = string(jsonOutput)
						}
					case "table":
						err = formatTable(&buf, res.Msg.Nodes, o.maxOutput, o.showInfo)
						if err != nil {
							queryResult = fmt.Sprintf("Failed to format table: %v", err)
						} else {
							queryResult = buf.String()
						}
					}
				}
			} else if strings.HasPrefix(strings.TrimSpace(script), "globsearch:") {
				// Remove the "globsearch:" prefix
				pattern := strings.TrimPrefix(strings.TrimSpace(script), "globsearch:")
				fmt.Printf("\nAssistant: I'll help you with that. I'm going to use this pattern:\n\"%s\"\n", pattern)

				req := connect.NewRequest(&apiv1.GetNodesByGlobRequest{Pattern: pattern})
				res, err := o.graphServiceClient.GetNodesByGlob(cmd.Context(), req)

				if err != nil {
					queryResult = fmt.Sprintf("Query failed: %v", err)
				} else if len(res.Msg.Nodes) == 0 {
					queryResult = "No results found"
				} else {
					switch o.output {
					case "json":
						jsonOutput, err := helpers.FormatNodeJSON(res.Msg.Nodes)
						if err != nil {
							queryResult = fmt.Sprintf("Failed to format JSON: %v", err)
						} else {
							queryResult = string(jsonOutput)
						}
					case "table":
						err = formatTableGlobSearch(&buf, res.Msg.Nodes, o.maxOutput, o.showInfo)
						if err != nil {
							queryResult = fmt.Sprintf("Failed to format table: %v", err)
						} else {
							queryResult = buf.String()
						}
					}
				}
			} else {
				queryResult = "Sorry the query failed, please try again."
			}
		}

		// Add results to chat history
		feedbackMsg := fmt.Sprintf("Here are the results of the query:\n%s\nWhat else would you like to know?", queryResult)
		messages = append(messages, openai.ChatCompletionMessage{
			Role:    openai.ChatMessageRoleAssistant,
			Content: feedbackMsg,
		})

		fmt.Println(feedbackMsg)
	}
}

// formatTable formats the nodes into a table and writes it to the provided writer.
func formatTable(w io.Writer, nodes []*apiv1.Node, maxOutput int, showInfo bool) error {
	table := helpers.NewTable(w, true)
	headers := []string{"Name", "Type", "ID"}
	if showInfo {
		headers = append(headers, "Info")
	}
	table.Header(headers)

	count := 0
	for _, node := range nodes {
		if count >= maxOutput {
			break
		}

		row := []string{
			node.Name,
			node.Type,
			strconv.FormatUint(uint64(node.Id), 10),
		}

		if showInfo {
			additionalInfo := helpers.ComputeAdditionalInfo(node)
			row = append(row, additionalInfo)
		}

		table.Append(row)
		count++
	}

	table.Render()
	return nil
}

// Add new function to format leaderboard table
func formatLeaderboardTable(w io.Writer, queries []*apiv1.Query, maxOutput int, showInfo bool) error {
	table := helpers.NewTable(w, true)
	headers := []string{"Name", "Type", "ID", "Output"}
	if showInfo {
		headers = append(headers, "Info")
	}
	table.Header(headers)

	count := 0
	for _, query := range queries {
		if count >= maxOutput {
			break
		}

		row := []string{
			query.Node.Name,
			query.Node.Type,
			strconv.FormatUint(uint64(query.Node.Id), 10),
			fmt.Sprint(len(query.Output)),
		}

		if showInfo {
			additionalInfo := helpers.ComputeAdditionalInfo(query.Node)
			row = append(row, additionalInfo)
		}

		table.Append(row)
		count++
	}

	table.Render()
	return nil
}

func formatTableGlobSearch(w io.Writer, nodes []*apiv1.Node, maxOutput int, showInfo bool) error {
	table := helpers.NewTable(w, false)
	table.Header([]string{"Name", "Type", "ID"})

	for i, node := range nodes {
		if i >= maxOutput {
			break
		}
		table.Append([]string{
			node.Name,
			node.Type,
			strconv.FormatUint(uint64(node.Id), 10),
		})
	}

	table.Render()
	return nil
}

// New creates and returns a new Cobra command for executing custom query scripts.
func New() *cobra.Command {
	o := &options{}

	cmd := &cobra.Command{
		Use:   "llm [query]",
		Short: "Create a chat session with an LLM to query the graph for leaderboards, queries, and globsearches",
		Long: `Ask questions about the graph in plain language; the model turns them into queries, leaderboards or
glob searches and Sapper runs them. Type 'exit' to end the session.

Works with any OpenAI-compatible chat API. For OpenAI set SAPPER_LLM_API_KEY (or OPENAI_API_KEY); for a local
server such as Ollama pass --base-url http://localhost:11434/v1 and a model it has, e.g. --model qwen2.5-coder.`,
		Args:              cobra.NoArgs,
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}

	o.AddFlags(cmd)

	return cmd
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
