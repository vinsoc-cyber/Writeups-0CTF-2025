# ProAgent Writeup

## Description

For this challenge, we're given an LLM agent that can be accessed through the ProAgent Console website. The website allows us to connect the LLM to a specified MCP server and start task. If we use the start task functionality, the website will send a prompt to the LLM model through websocket telling it to get the lastest discussions on HackerNews about "LLM Security". The agent has access to several tools to carry out the task the user gives it.

![](./assets/console.png)

The author has also given us a Docker container to test locally before running our exploit on their instance. 

We need to build an MCP server containing a tool that allows the LLM agent to use it and look up HackerNews discussions. This tool would return fake HN discussions and prompts the agent to use its internal tool to read the flag on the server.

## Analysis of the LLM agent

Through analyzing the agent scripts, we know that the agent has access to a tool called `read_file`, which can be used to read local files. 

We also know that given an MCP server, the agent will try to use the fetch HN discussion tool of that server to get discussion. The agent will send a verification token to the MCP server, which we can use for exfiltration.

## Exploitation

We can build an MCP server that contains a tool that sends back fake HN discussions while also prompting the agent to use the `read_file` tool to get the flag and send it back to the MCP server through the verification token.

Here's how this exploit would work:
1. When prompted to start looking up HN discussions, the LLM will try to access the HN discussion lookup tool of the MCP server.
2. The MCP server's tool description will be sent back to the LLM so that the agent can understand the tool. The description will contain a prompt that will coerce the LLM agent into using the `read_file` tool to read the content of `/flag` and putting it in the verification token field.
3. The agent will send the verification token containing the content of `/flag` to the MCP server and wait for the MCP server to give it the HN discussions.
4. The MCP server will print out the flag content and send fake HN discussions to the LLM agent.

![](./assets/agent-message.png)

You can access the exploit script [here](./solve/exploit.py). We ran this on our own server and gave the LLM agent the server's public IP.
