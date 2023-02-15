defmodule PDSZ do
  @moduledoc """
  Documentation for `PDSZ`.  This module allows for creation of creds on the Zetonium blockchain, getting balances for a give set of creds, and transferring balances.

  Each function leverages native PDS api endpoints (no intermediary wrapper).

  """

  @service URI.parse("https://pdsapi.dase.io:8081/api/")
  @rpc URI.parse("https://pdsapi.dase.io:5201")
  @aws_wrapper_api_base URI.parse("https://txsleuth.com")
  @vault_id 2

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
  def credz(reg \\ false) do
    if !reg do
      %Credz{
        :zuid => "0x5b542b79e27ac52a0c3eeeac4559863d130fffdc",
        :zpub =>
          "0x095cd9d2a2a463a528224da2e69b3a47c757163e544901bbd114622df1cabcc1e919ffde85d5f747d7a635a0f0c321c1030fbc61b36284da87fa0065179fbdc0",
        :zpri => "0xe64c8698fb628e5b7e07d941e85200af259e9856a5dfc7ef83587756d45ef972"
      }
    else
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

          %Credz{
            :zuid => String.downcase(z["userId"]),
            :zpri => z["prvKey"],
            :zpub => z["pubKey"]
          }

        {:ok,
         %HTTPoison.Response{
           body: body
         }} ->
          z = Poison.decode!(body)
          %Credz{:zuid => "error", :zpri => "error", :zpub => "error"}

        _ ->
          %Credz{:zuid => "error", :zpri => "error", :zpub => "error"}
      end
    end
  end

  @doc """
  Get Zetonium balance.  Returns a map, snake case key.

  ## Examples

      iex> PDSZ.balance(zuid)

      %{"gold_leos" => "0", "silver_leos" => "0"}


  """

  def balance(z \\ credz(false)) do
    the_url_path = "balances?zetoniumUserId=#{z.zuid}"
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

  @doc """
  Takes JSON payload from the pds blockchain api and maps to a generic license struct.  Returns just the struct.
  """
  def convert_license_generic(license) do
    related_dab_id =
      if Map.has_key?(license, "relatedDabId") do
        elem(Integer.parse(license["relatedDabId"]), 0)
      else
        nil
      end

    %GenericLicense{
      asset_id: license["assetId"],
      tag_id: license["tagId"],
      related_dab_id: related_dab_id,
      total_usage_count: license["totalUsageCount"],
      buyer_id: String.downcase(license["buyerId"]),
      seller_id: String.downcase(license["sellerId"]),
      license_type: license["licenseType"],
      date_time: DateTime.from_iso8601(license["dateTime"])
    }
  end

  def register(uuid, files, user \\ credz(false)) do
    case_id = register_gchat_bundle(uuid, uuid, user)["newId"]

    do_upload = fn file ->
      {_signature, vault_url, everything} = get_access_ticket(user)
      headers = get_upload_session(everything, vault_url)
      asset_name = upload_file(vault_url, headers["vault-session-id"], file)

      # "vtid=1:|:avid=:|:asid=5225fb689f.ed1aef1da30d1537a848f8d1187bd3e746bd3d08bb933bc6239f02e47e6d21ba0f55faf43603b820fab6d2b2cff62b67c05103ed1026f56642284231c650dd9eda04d2281847ac0d4023313466de4f5022006a4d4ce394a86e31386d0b5b2dc8c1cfbabb9d2e63042928f8ba2f3f727e:|:mime=image/svg+xml"
      pds_demarcation_hack = ":|:"

      asset_url =
        "vtid=#{@vault_id}#{pds_demarcation_hack}avid=#{pds_demarcation_hack}asid=#{asset_name}#{pds_demarcation_hack}"

      new_dab = register_asset(user, asset_url, Path.basename(file), file)

      submit_case_apply(
        user,
        case_id,
        new_dab
      )
    end

    Enum.each(files, &do_upload.(&1))
  end

  defp submit_case_apply(user, case_id, asset_id) do
    api_path =
      "/case/apply/#{user.zuid}/private_key/#{user.zpri}/case_id/#{case_id}/asset_id/#{asset_id}"

    u_api_path = URI.parse(api_path)
    aws_url = URI.merge(@aws_wrapper_api_base, u_api_path)

    headers = [{"Content-Type", "application/json"}]
    params = %{}

    case HTTPoison.get(aws_url, headers, params: params) do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         body: body
       }} ->
        Poison.decode!(body)

      _ ->
        %{}
    end
  end

  defp get_access_ticket(user) do
    the_url_path =
      "tokens?accessType=UPLOAD&userId=#{user.zuid}&userPubKey=#{user.zpub}&vaultId=#{@vault_id}"

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
        signature = Poison.decode!(body)["signature"]
        vault_url = Poison.decode!(body)["vaultUrl"]

        dec_payload = Poison.decode!(body)
        ree_payload = to_string(Poison.encode!(dec_payload))
        enc_ree = Base.url_encode64(ree_payload)

        {signature, vault_url, enc_ree}

      _ ->
        {nil, nil, nil}
    end
  end

  defp get_upload_session(access_ticket_encoded, vault_url) do
    the_url_path = "/getsession?ticket=#{access_ticket_encoded}"
    complete_url_path = URI.merge(vault_url, the_url_path)

    headers = [{"Content-Type", "application/json"}]
    params = %{}

    res = HTTPoison.get(complete_url_path, headers, params: params)

    case res do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         headers: headers,
         body: _body
       }} ->
        Enum.into(headers, %{})

      _ ->
        %{}
    end
  end

  defp upload_file(vault_url, session_id, path_to_file) do
    the_url_path = "/upload?sid=#{session_id}"
    complete_url_path = URI.merge(vault_url, the_url_path)
    headers = [{"Content-Type", "application/json"}]

    form =
      {:multipart,
       [
         {:file, path_to_file,
          {"form-data", [{:name, "file"}, {:filename, Path.basename(path_to_file)}]}, []}
       ]}

    res = HTTPoison.post(complete_url_path, form, headers, [])

    case res do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         headers: _headers,
         body: body
       }} ->
        Poison.decode!(body)["asset"]["name"]

      _ ->
        nil
    end
  end

  defp register_asset(user, asset_url, asset_description, file) do
    the_url_path = "assets/create"
    complete_url_path = URI.merge(@service, the_url_path)

    headers = [{"Content-Type", "application/json"}]

    initial_hash_state = :crypto.hash_init(:sha256)

    sha256 =
      File.stream!(file, [], 2048)
      |> Enum.reduce(initial_hash_state, &:crypto.hash_update(&2, &1))
      |> :crypto.hash_final()

    formatted_sha256 = Base.encode16(sha256, case: :lower)
    formatted_sha256_with_leading_0X = "0x#{formatted_sha256}"

    form = %{
      ownerId: user.zuid,
      ownerCredentials: user.zpri,
      dataArr: [
        %{
          assetContentType: "application/json",
          dataHash: formatted_sha256_with_leading_0X,
          assetUrl: asset_url,
          description: asset_description
        }
      ]
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
        Poison.decode!(body)

      _ ->
        %{}
    end
  end

  defp register_gchat_bundle(title, description, user) do
    form = %{
      userId: user.zuid,
      publicKey: user.zpub,
      privateKey: user.zpri,
      title: title,
      description: description
    }

    api_path = "/case/create"
    headers = [{"Content-type", "application/json"}]
    u_api_path = URI.parse(api_path)
    aws_url = URI.merge(@aws_wrapper_api_base, u_api_path)
    encform = JSON.encode!(form)
    sencform = to_string(encform)

    case HTTPoison.post(aws_url, sencform, headers, []) do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         body: body
       }} ->
        Poison.decode!(body)

      {:ok, %HTTPoison.Response{body: body}} ->
        Poison.decode!(body)

      {:error, %HTTPoison.Error{reason: reason}} ->
        Poison.decode!(reason)

      _ ->
        Poison.decode!(~s|{"post call": "case create", "error": "guard undetermined"}|)
    end
  end

  def get_all_licenses(user \\ credz(false)) do
    lscout = get_licenses(1, 1, user.zuid)
    tc = lscout.total_count
    range_bound = tc / 100

    agg_task =
      Task.async(fn ->
        if tc == 0 do
          %{:total_count => 0, :licenses => []}
        else
          Enum.reduce(1..ceil(range_bound), %{}, fn current_page, _hm ->
            get_licenses(current_page, 100, user.zuid)
          end)
        end
      end)

    all_licenses = Task.await(agg_task, :infinity)
    all_licenses
  end

  def get_licenses(current_page, per_page, zetonium_user_id \\ credz(false).zuid) do
    api_path = "licenses"

    u_api_path = URI.parse(api_path)
    pds_url = URI.merge(@service, u_api_path)

    headers = [{"Content-Type", "application/json"}]

    params = %{
      userId: zetonium_user_id,
      limit: per_page,
      offset: (current_page - 1) * per_page
    }

    case HTTPoison.get(pds_url, headers, params: params) do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         body: body
       }} ->
        %{
          :total_count => Poison.decode!(body)["totalCount"],
          :licenses =>
            Enum.map(Poison.decode!(body)["licenses"], fn license ->
              convert_license_generic(license)
            end)
        }

      _ ->
        %{:total_count => 0, :licenses => []}
    end
  end

  def get_asset(asset_id, user \\ credz(false)) do
    api_path = "/asset/#{user.zuid}/asset_id/#{asset_id}"

    u_api_path = URI.parse(api_path)
    aws_url = URI.merge(@aws_wrapper_api_base, u_api_path)

    headers = [{"Content-Type", "application/json"}]
    params = %{}

    case HTTPoison.get(aws_url, headers, params: params) do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         body: body
       }} ->
        Poison.decode!(body)

      {:ok, %HTTPoison.Response{body: body}} ->
        Poison.decode!(body)

      {:error, %HTTPoison.Error{reason: reason}} ->
        Poison.decode!(reason)

      _ ->
        Poison.decode!(~s|{"get call": "asset", "error": "guard undetermined"}|)
    end
  end

  def get_tag(tag_id) do
    api_path = "tags?tagIds=#{tag_id}&queryOption=by_ids"
    u_api_path = URI.parse(api_path)
    aws_url = URI.merge(@service, u_api_path)

    headers = [{"Content-Type", "application/json"}]
    params = %{}

    case HTTPoison.get(aws_url, headers, params: params) do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         body: body
       }} ->
        Poison.decode!(body)

      {:ok, %HTTPoison.Response{body: body}} ->
        Poison.decode!(body)

      {:error, %HTTPoison.Error{reason: reason}} ->
        Poison.decode!(reason)

      _ ->
        Poison.decode!(~s|{"get call": "asset", "error": "guard undetermined"}|)
    end
  end

  def get_assets(user \\ credz(false)) do
    licenses = get_all_licenses(user)

    licenses.licenses
    |> Enum.filter(fn l -> l.asset_id != nil end)
    |> Enum.map(fn l -> get_asset(l.asset_id, user) end)
  end

  def get_bundles(user \\ credz(false)) do
    licenses = get_all_licenses(user)

    licenses.licenses
    |> Enum.filter(fn l ->
      l.tag_id != nil && l.license_type != "ROYALTY" && l.license_type != "SATCREATE"
    end)
    |> Enum.map(fn l -> get_tag(l.tag_id) end)
  end

  def get_bundle_members(tag_id, user \\ credz(false)) do
    complete_url_path = URI.parse(@rpc)

    headers = [{"Content-Type", "application/json"}]

    params = %{
      :rootTagId => tag_id,
      :tagId => tag_id,
      :userId => user.zuid,
      :userCredentials => user.zpri
    }

    form = %{
      :jsonrpc => "2.0",
      :method => "exploreLabelsHierarchy",
      :id => 1,
      :params => params
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
        Poison.decode!(body)

      _ ->
        %{}
    end
  end

  def view_asset(asset_id, user \\ credz(false)) do
    ticket_meister =
      ~s({"buyerId":"#{user.zuid}","dabIds":[#{asset_id}],"sellerIds":["#{user.zuid}"]})

    signature = sign(ticket_meister, user.zpri)
    is_valid = verify(signature, ticket_meister, user.zpub)

    url =
      valid_sig(
        is_valid,
        user.zuid,
        user.zpub,
        asset_id,
        user.zuid,
        signature
      )
      |> URI.parse()


    headers = [{"Content-Type", "application/json"}]

    params = %{}

    res = HTTPoison.get(url, headers, params: params)

    case res do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         headers: _headers,
         body: body
       }} ->
        Poison.decode!(body)

      _ ->
        %{}
    end
  end

  defp access_asset_call_complete(_vault_url, dsid)
       when is_nil(dsid) do
    IO.puts(
      "There was an error in your call to get an access ticket.  Either download sid not set, or vault url not set (or both)."
    )
  end

  defp access_asset_call_complete(vault_url, dsid) do
    the_url_path = "download?sid=#{dsid}"
    dvvu = URI.merge(vault_url, the_url_path)
    dvvu
  end

  defp the_session_call(vault_url, encoded_shit) do
    headers = [{"Content-Type", "application/json"}]

    params = %{
      ticket: encoded_shit
    }

    api_path = "getsession"
    u_api_path = URI.parse(api_path)
    the_url = URI.merge(vault_url, u_api_path)

    case HTTPoison.get(the_url, headers, params: params) do
      {:ok,
       %HTTPoison.Response{
         headers: headers
       }} ->
        vid =
          Enum.filter(headers, fn t ->
            elem(t, 0) == "vault-session-id"
          end)
          |> List.first()
          |> elem(1)

        vky =
          Enum.filter(headers, fn t ->
            elem(t, 0) == "vault-session-key"
          end)
          |> List.first()
          |> elem(1)

        {vid, vky}

      _ ->
        {nil, nil}
    end
  end

  defp valid_sig(
         true,
         user_id,
         public_key,
         asset_id,
         owner_id,
         signature
       ) do
    {vault_url, dsid} =
      submit_asset_access(
        user_id,
        public_key,
        asset_id,
        owner_id,
        signature
      )

    access_asset_call_complete(vault_url, dsid)
  end

  defp valid_sig(false, _, _, _, _, _) do
    IO.puts("There was an error with your signature.")
  end

  def submit_asset_access(
        user_id,
        public_key,
        asset_id,
        owner_id,
        signature
      ) do
    api_path = "tokens"

    u_api_path = URI.parse(api_path)
    the_url = URI.merge(@service, u_api_path)


    headers = [{"Content-Type", "application/json"}]

    params = %{
      accessType: "ACCESS",
      userId: user_id,
      publicKey: public_key,
      dabIds: asset_id,
      sellerIds: owner_id,
      argsBuyerSignature: signature
    }

    res = HTTPoison.get(the_url, headers, params: params)

    case res do
      {:ok,
       %HTTPoison.Response{
         status_code: 200,
         headers: _headers,
         body: body
       }} ->
        inner_res = Poison.decode!(body) |> List.first()

        if inner_res["vaultUrl"] != nil do
          vault_url = inner_res["vaultUrl"]
          pj = Poison.encode!(inner_res) |> to_string() |> Base.encode64()
          {dsid, _dkey} = the_session_call(vault_url, pj)

          {vault_url, dsid}
        else
          {nil, nil}
        end

      _ ->
        {nil, nil}
    end
  end

  def sign(json_data, raw_private_key) do
    private_key_clipped = String.slice(raw_private_key, 2, String.length(raw_private_key))
    {:ok, private_key} = Curvy.Util.decode(private_key_clipped, :hex)
    hjd = hash(json_data)

    Curvy.sign(json_data, private_key, encoding: :hex, hash: :sha256)
  end

  def verify(sig, json_data, raw_public_key) do
    public_key_clipped = String.slice(raw_public_key, 2, String.length(raw_public_key))

    public_key_revised =
      if String.length(public_key_clipped) < 132 && !String.starts_with?(public_key_clipped, "04") do
        "04" <> public_key_clipped
      else
        public_key_clipped
      end

    {:ok, public_key} = Curvy.Util.decode(public_key_revised, :hex)
    Curvy.verify(sig, json_data, public_key, encoding: :hex, hash: :sha256)
  end

  def hash(msg) do
    :crypto.hash(:sha256, msg) |> Base.encode16() |> String.downcase()
  end
end
