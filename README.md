# TLDR

If you just pull the repo, and have elixir running, check out the LiveBook:

https://github.com/edzlabs/sampler/blob/main/pdszlivebook.livemd  

and just 

```
iex -S mix
```

# CHAT GPT SECRET

you need a bearer key from chat gpt, and in config, please create a file

dev.exs  

and paste the following  

```
import Config

config :pdsz,
secret_key: "Bearer sk-youkeystuffgoeshere"

```


# PDSZ

An app for you to learn PDS basics

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `pdsz` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:pdsz, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/pdsz>.

## Create a new app

```
. ~/.profile

mix new exercise --module EXERCISE  

```

## Try it out

```
cd pdsz  

MIX_ENV=dev iex -S mix  

PDSZ.hello

```

## If you're going to make you're own LiveBook on this elixir app

```
iex --sname pdsz --cookie pdszcookie -S mix

```

from livebook dir
```
MIX_ENV=prod mix phx.server
```

## If you're going to make you're own LiveBook and you have generated a LiveView app

```
iex --sname pdsz --cookie pdszcookie -S mix phx.server  
PDSZ.hello
```

## Add to you deps  

{:httpoison, "~> 1.8"},
{:poison, "~> 5.0"},
{:json, "~> 1.4"}

and then  

```
mix deps.get
```