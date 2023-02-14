defmodule GenericLicense do
  defstruct [
    :asset_id,
    :tag_id,
    :related_dab_id,
    :total_usage_count,
    :buyer_id,
    :seller_id,
    :license_type,
    date_time: elem(DateTime.now("Etc/UTC"), 1)
  ]
end
