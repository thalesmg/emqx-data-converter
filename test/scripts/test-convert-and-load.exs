#!/usr/bin/env elixir

# test helpers
defmodule TH do
  require Logger

  @container_name "emqx-data-converter"

  def converter_path() do
    Path.absname("./emqx_data_converter")
  end

  def list_test_configs() do
    Path.wildcard("test/data/*.json")
  end

  def wrap_if(_x, false), do: []
  def wrap_if(x, true), do: List.wrap(x)

  def convert!(input_filepath, opts \\ []) do
    Logger.info(%{input: input_filepath, msg: "converting_input", opts: opts})

    data_files_dir = Keyword.get(opts, :data_files_dir)

    cmd =
      List.flatten([
        "-o",
        "/tmp",
        wrap_if(["--data-files-dir", data_files_dir], !!data_files_dir),
        input_filepath
      ])

    Logger.debug(%{msg: "convertion_cmd", cmd: cmd})

    {:ok, output} = run(converter_path(), cmd)

    IO.puts(output)

    res = Regex.run(~r/backup file: (?<filepath>.+)/, output, capture: ["filepath"])

    case res do
      [filepath] ->
        {:ok, filepath}

      _ ->
        {:error, {:could_not_extract_filepath, output}}
    end
  end

  def place_files(input_filepath, outdir) do
    Logger.info(%{input: input_filepath, msg: "importing_input"})
    File.mkdir_p!("converted")
    {:ok, _} = run("bash", ["-c", "tar -C converted -xvf #{input_filepath} --strip-components=1"])

    {:ok, _} =
      run_in_container([
        "cp #{outdir}/cluster.hocon data/configs/cluster.hocon",
        "mkdir -p data/authz/",
        "cp #{outdir}/authz/acl.conf data/authz/acl.conf"
      ])

    :ok
  end

  def import!(input_filepath) do
    outdir = "/opt/data/converted"

    :ok = place_files(input_filepath, outdir)

    Logger.info(%{msg: "starting_emqx"})
    :ok = start_emqx()

    Enum.each(Path.wildcard("converted/mnesia/*"), fn table_path ->
      :ok =
        table_path
        |> Path.basename()
        |> import_table(outdir)
    end)
  end

  def start_emqx(opts \\ []) do
    wait_s = Keyword.get(opts, :wait_s, 15)

    cmd = [
      "export EMQX_WAIT_FOR_START=#{wait_s}",
      # "export DEBUG=2",
      "docker-entrypoint.sh emqx foreground"
    ]

    Logger.debug(%{msg: "starting_emqx", cmd: cmd})

    # stupid and ugly hack because, for unknown reasons, `emqx start` hangs for ~ 62
    # seconds when running before starting locally, but runs fine in CI...  🫠
    spawn_link(fn ->
      run_in_container(cmd)
    end)

    Enum.reduce_while(1..wait_s, :error, fn _, acc ->
      Process.sleep(1_000)

      case run_in_container("emqx ctl status") do
        {:ok, output} ->
          IO.puts(output)

          if output =~ "is started" do
            {:halt, :ok}
          else
            {:cont, acc}
          end

        _ ->
          {:cont, acc}
      end
    end)
  end

  def import_table(table, outdir) do
    Logger.info(%{msg: "importing_mnesia_table", table: table})

    {:ok, output} =
      run_in_container(~s|emqx eval 'mnesia:restore("#{outdir}/mnesia/#{table}", [])'|)

    {:ok, val} = parse_erl(output)

    if match?({:atomic, [_]}, val) do
      Logger.info(%{msg: "mnesia_import_successful", result: val})
      :ok
    else
      {:error, {:bad_result, table, val}}
    end
  end

  def parse_erl(str) do
    str = String.trim(str)

    str =
      if String.ends_with?(str, ".") do
        str
      else
        str <> "."
      end

    with {:ok, tokens, _} <- str |> to_charlist() |> :erl_scan.string(),
         {:ok, ast} <- :erl_parse.parse_exprs(tokens),
         {:value, val, _env} <- :erl_eval.exprs(ast, _env = []) do
      {:ok, val}
    else
      err ->
        {:error, {:bad_erl_str, str, err}}
    end
  end

  def start_container(image) do
    Logger.info(%{msg: "starting_container", image: image})

    run(
      "docker",
      [
        "run",
        "--rm",
        "-d",
        "-v",
        "#{File.cwd!()}:/opt/data",
        # in case we want to execute RPC via gen_rpc
        # "-p", "5370:5369",
        # dashboard
        "-p",
        "48083:18083",
        "--name",
        @container_name,
        image,
        "bash",
        "-c",
        "tail -f /dev/null"
      ]
    )
  end

  def stop_container() do
    Logger.info(%{msg: "stopping_container"})
    {:ok, _} = run("docker", ["rm", "-f", @container_name])
    Logger.info(%{msg: "container_stopped"})
  end

  def run_in_container(cmd, opts \\ []) do
    cmd =
      cmd
      |> List.wrap()
      |> Enum.join(" ; ")

    run("docker", ["exec", @container_name, "bash", "-c", cmd], opts)
  end

  def run(command, args, opts \\ []) do
    {out, exit_code} = System.cmd(command, args, opts)

    if exit_code != 0 do
      {:error, exit_code, out}
    else
      {:ok, out}
    end
  end
end

Mix.install([{:httpoison, "2.2.1"}, {:jason, "1.4.4"}])

ExUnit.start()

defmodule Tests do
  use ExUnit.Case

  require Logger

  @moduledoc """
  Exploring locally:

      image = "emqx/emqx-enterprise:5.8.0"
      TH.start_container(image)
      outdir = "/opt/data/converted"
      path = "test/data/barebones.json"
      {:ok, converted_path} = TH.convert!(path)
      TH.place_files(converted_path, outdir)

  After this, `docker exec -it emqx-data-converter bash`

  Or:

      TH.import_table("emqx_app", outdir)
  """

  # exposed by docker
  @api_port 48083

  def api_req!(method, path, body \\ "") do
    api_user = "app_id"
    api_pass = "4mVZvVT9CnC6Z3AYdk9C07Ecz9AuBCLblb43kk69BcxbBhP"
    authn64 = Base.encode64("#{api_user}:#{api_pass}")

    HTTPoison.request!(
      method,
      "http://localhost:#{@api_port}/api/v5/#{path}",
      body,
      [{"Authorization", "Basic #{authn64}"}]
    )
  end

  setup_all do
    {:ok, %{image: System.fetch_env!("EMQX_IMAGE")}}
  end

  setup %{image: image} do
    TH.stop_container()
    on_exit(&TH.stop_container/0)
    {:ok, _} = TH.start_container(image)
    :ok
  end

  test "barebones" do
    path = "test/data/barebones.json"
    {:ok, converted_path} = TH.convert!(path)
    on_exit(fn -> File.rm(converted_path) end)
    :ok = TH.import!(converted_path)
  end

  test "mnesia, redis, postgres authn/authz" do
    path = "test/data/auth-builtin-redis-postgres1.json"
    {:ok, converted_path} = TH.convert!(path)
    on_exit(fn -> File.rm(converted_path) end)
    :ok = TH.import!(converted_path)

    # import application should start working
    resp = api_req!(:get, "mqtt/retainer/messages")

    assert %HTTPoison.Response{status_code: 200} = resp
  end

  # Retained messages from ram copies.  Has 1 "real" message and 3 system messages.
  test "retained messages : ram" do
    path = "test/data/auth-builtin-redis-postgres1.json"
    {:ok, converted_path} = TH.convert!(path, data_files_dir: "test/data/retainer_ram1")
    on_exit(fn -> File.rm(converted_path) end)
    :ok = TH.import!(converted_path)

    assert {:ok, _} = TH.run_in_container("docker-entrypoint.sh emqx ctl retainer reindex start")

    resp = api_req!(:get, "mqtt/retainer/messages")

    assert %HTTPoison.Response{status_code: 200} = resp
    messages = Jason.decode!(resp.body)

    assert %{"data" => [_, _, _, _]} = messages
  end
end
