defmodule PDSChatGPT do
  @moduledoc """
  Documentation for `PDSChatGPT`.  This is useful for registering and giving provenance to your ChatGPT inputs and outputs.

  Registering a prompt and a result set means saving each in a file and loading those files in a vault - that's two distinct assets (files).

  They are logically related with a UUID on chain tag, which serves as a folder mechanism.  So, there's a call to generate a TAG, with the UUID as the Description.

  """

  @service URI.parse("https://api.openai.com/v1/")

  @doc """
  Do PDS register of tag (uuid), and the two assets (prompt and response), and apply the tag to those assets.

  """
  def register(uuid) do
    IO.puts("Need to register this tag: #{uuid}")
    IO.puts("Need to register this prompt: /tmp/#{uuid}-prompt.txt")
    IO.puts("Need to register this response: /tmp/#{uuid}-response.txt")

    latest_publications = ["/tmp/#{uuid}-prompt.txt", "/tmp/#{uuid}-response.txt"]

    PDSZ.register(uuid, latest_publications)
  end

  @doc """
  Save prompt and response

  """
  def save_prompt_and_response(prompt, response) do
    uuid = UUID.uuid1()
    IO.puts("when we get around to writing a file, here's its name")
    IO.inspect(uuid)

    {:ok, prompt_file} = File.open("/tmp/#{uuid}-prompt.txt", [:write])
    {:ok, response_file} = File.open("/tmp/#{uuid}-response.txt", [:write])

    response_concat = Enum.map(response, fn i -> i["text"] end)

    IO.binwrite(prompt_file, Poison.encode!(%{:prompt => prompt}))
    IO.binwrite(response_file, Poison.encode!(%{:response => response_concat}))

    File.close(prompt_file)
    File.close(response_file)
    uuid
  end

  @doc """
  Send prompt to Chat GPT

  """
  def send_to_chat_gpt(register, prompt \\ "Why is AI overrated?") do
    chat_gpt_key_secret = Application.fetch_env!(:pdsz, :secret_key)

    headers = [{"Content-type", "application/json"}, {"Authorization", chat_gpt_key_secret}]

    the_url_path = "completions"
    complete_url_path = URI.merge(@service, the_url_path)

    form = %{
      model: "text-davinci-001",
      prompt: prompt,
      temperature: 0.4,
      max_tokens: 256,
      top_p: 1,
      frequency_penalty: 0,
      presence_penalty: 0
    }

    encform = JSON.encode!(form)
    sencform = to_string(encform)

    res = HTTPoison.post(complete_url_path, sencform, headers, [])

    case res do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         body: body
       }} ->
        if register do
          save_prompt_and_response(prompt, Poison.decode!(body)["choices"]) |> register()
        end

        {:ok, Poison.decode!(body)["choices"]}

      {:ok,
       %HTTPoison.Response{
         body: body
       }} ->
        {:error, Poison.decode!(body)}

      _ ->
        {:error, res}
    end
  end
end
