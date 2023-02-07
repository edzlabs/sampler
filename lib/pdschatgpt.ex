defmodule PDSChatGPT do
  @moduledoc """
  Documentation for `PDSChatGPT`.
  """

  @chat_gpt_key_secret Application.fetch_env!(:pdsz, :secret_key)

  @service URI.parse("https://api.openai.com/v1/")

  @doc """
  Hello world.

  ## Examples

      iex> PDSZ.hello()
      :world

  """
  def hello do
    :world
  end

  @doc """
  Send prompt to Chat GPT
      
  """
  def send_to_chat_gpt(prompt) do
    headers = [{"Content-type", "application/json"}, {"Authorization", @chat_gpt_key_secret}]

    the_url_path = "completions"
    complete_url_path = URI.merge(@service, the_url_path)

    form = %{
      model: "text-davinci-001",
      prompt: prompt,
      temperature: 0.4,
      max_tokens: 64,
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
        z = Poison.decode!(body)
        IO.inspect(z)

      {:ok,
       %HTTPoison.Response{
         body: body
       }} ->
        z = Poison.decode!(body)
        IO.puts("got a badish response from pds")
        IO.inspect(z)

      _ ->
        IO.puts("got a bad response from pds")
        IO.inspect(res)
    end
  end

  @doc """
  Get Zetonium balance.

  ## Examples

      iex> PDSZ.balance(zuid)
      

  """

  def balance(zuid) do
    the_url_path = "balances?zetoniumUserId=#{zuid}"
    complete_url_path = URI.merge(@service, the_url_path)

    headers = [{"Content-Type", "application/json"}]
    params = %{}
    res = HTTPoison.get(complete_url_path, headers, params: params)

    case res do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         body: body
       }} ->
        if body == "", do: %{}, else: Poison.decode!(body)

      _ ->
        Poison.decode!(~s|{"get call": "balances", "error": #{IO.inspect(res)}}|)
    end
  end
end
