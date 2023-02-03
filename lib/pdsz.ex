defmodule PDSZ do
  @moduledoc """
  Documentation for `PDSZ`.
  """

  @service URI.parse("https://pdsapi.dase.io:8081/api/")

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
  Get Zetonium creds.

  ## Examples

      iex> PDSZ.credz()
      %{
        zpri: "0xe64c8698fb628e5b7e07d941e85200af259e9856a5dfc7ef83587756d45ef972",
        zpub: "0x095cd9d2a2a463a528224da2e69b3a47c757163e544901bbd114622df1cabcc1e919ffde85d5f747d7a635a0f0c321c1030fbc61b36284da87fa0065179fbdc0",
        zuid: "0x5b542b79e27ac52a0c3eeeac4559863d130fffdc"
      }
      

  """
  def credz do
    headers = [{"Content-type", "application/json"}]

    the_url_path = "users/create"
    complete_url_path = URI.merge(@service, the_url_path)

    form = %{blockchainType: "ZETONIUM"}
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

        %{:zuid => String.downcase(z["userId"]), :zpri => z["prvKey"], :zpub => z["pubKey"]}

      {:ok,
       %HTTPoison.Response{
         body: body
       }} ->
        z = Poison.decode!(body)
        IO.puts("got a badish response from pds")
        IO.inspect(z)
        %{:zuid => "error", :zpri => "error", :zpub => "error"}

      _ ->
        IO.puts("got a bad response from pds")
        IO.inspect(res)
        %{:zuid => "error", :zpri => "error", :zpub => "error"}
    end
  end
end