defmodule JwksRsa.Application do
  @moduledoc false

  use Application
  import Supervisor.Spec, only: [worker: 2]

  def start(_type, _args) do
    children = [
      # {JwksRsa.Worker, arg}
      worker(Cachex, [:jwks_rsa_cache, []])
    ]

    opts = [strategy: :one_for_one, name: JwksRsa.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
