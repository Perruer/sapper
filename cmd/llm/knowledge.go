package custom

// knowledge explains the query language to the model. It used to live in a vector database that the
// server filled and the client searched with OpenAI embeddings; it is short enough to send whole.
var knowledge = []string{
	"To query dependencies of a package, use the format, and only output the query: dependencies library pkg:<package_name>. All three are necessary.",
	"To find dependents of a package, use the format, and only output the query: dependents library pkg:<package_name>. All three are necessary.",
	"For vulnerabilities related to a package, use the format, and only output the query: dependencies vuln pkg:<package_name>. All three are necessary.",
	"Combine queries using logical operators like and, or, and xor. All three are necessary.",
	"When using 'and', both conditions must be true. For example, and only output the query: dependencies library pkg:A and dependencies library pkg:B.",
	"When using 'or', at least one of the conditions must be true. For example, and only output the query: dependencies library pkg:A or dependencies library pkg:B.",
	"Use 'xor' to indicate that only one of the conditions can be true. For example, and only output the query: dependencies library pkg:A xor dependencies library pkg:B.",
	"You can chain multiple queries together. For example, and only output the query: dependencies library pkg:A and dependents library pkg:B or vulnerabilities vuln pkg:C.",
	"Package names can include versioning information. For example, and only output the query: dependencies library pkg:example-lib@1.0.0.",
	"Ensure that all keywords are used correctly. The keywords are: dependencies, dependents, library, vuln, xor, or, and.",
	"If a query does not specify a package name, it cannot be processed. Always include a package name in your queries.",
	"To check for multiple vulnerabilities across different packages, you can use, and only output the query: dependencies vuln pkg:A or dependencies vuln pkg:B.",
	"When using 'or', 'and', or 'xor', to take the answer of multiple queries and use an binary operator on the whole result with another query, or another set of queries, you can wrap a set of queries in brackets (), these can also be nested. Example: ((dependencies library pkg:A and dependencies library pkg:B) or (dependencies library pkg:C and dependencies library pkg:D)) and (dependents library pkg:E).",
	"Leaderboard queries are a different type of query, they run queries for every single node in the graph and return a sorted list based of length of the result.",
	"To run a leaderboard query, it is quite similar to a regular query, but instead of runing somthing like depedencies library pkg:A, you would run dependencies library. This would create a leaderboard which is sorted by each node's dependencies of type library.",
	"Leaderboards format are basicaly the same as a query, just if you do not include the node name for the last part of the query, it fills it with the node we are using for the leaderboard, which is every single node in the leaderboard. This means that to make a proper leaderboard we should have at least one part that does not include a node name, we can still combine this with another query. For example: (dependencies library) and (dependents library pkg:github.com/sigstore/cosign) would create a leaderboard sorted by the number of dependencies a project has that is shared with cosign. We can also repeat this 2 part query multiple times, for example : dependencies library and dependents library would work as well.",
	"If the user, or you are not sure about what the node's name is, you can use the glob pattern to search for nodes. For example, if you want to search for all nodes that start with 'github.com/sigstore', you can use the pattern 'github.com/sigstore*'. Try to get as many nodes as possible, so if they tell you the name is cosign, and maybe the org is sigstore, you can use '*cosign*', since it will match all nodes that contain cosign, since they are not sure about the org.",
	"When glob seaching never assume the position of anything, so wrap everything can in ** on both sides.",
}
