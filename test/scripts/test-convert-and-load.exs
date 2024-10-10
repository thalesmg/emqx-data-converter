#!/usr/bin/env elixir

defmodule Test.ConvertAndLoad do
  require Logger

  @container_name "emqx-data-converter"

  def converter_path() do
    Path.absname("./emqx_data_converter")
  end

  def list_test_configs() do
    Path.wildcard("test/data/*.json")
  end

  def convert!(input_filepath) do
    Logger.info(%{input: input_filepath, msg: "converting_input"})
    {:ok, output} = run(converter_path(), [
      "-o", "/tmp",
      input_filepath
    ])
    res = Regex.run(~r/backup file: (?<filepath>.+)/, output, capture: ["filepath"])
    case res do
      [filepath] ->
        {:ok, filepath}

      _ ->
        {:error, {:could_not_extract_filepath, output}}
    end
  end

  def import!(input_filepath) do
    Logger.info(%{input: input_filepath, msg: "importing_input"})
    File.mkdir_p!("converted")
    {:ok, _} = run("bash", ["-c", "tar -C converted -xvf #{input_filepath} --strip-components=1"])
    outdir = "/opt/data/converted"

    {:ok, _} =
      run_in_container([
        "cp #{outdir}/cluster.hocon data/configs/cluster.hocon",
        "mkdir -p data/authz/",
        "cp #{outdir}/authz/acl.conf data/authz/acl.conf"
      ])

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

    res =
      run_in_container("env EMQX_NODE_NAME=$(<nodename) EMQX_WAIT_FOR_START=#{wait_s} emqx start")

    case res do
      {:ok, _} ->
        :ok

      {:error, _, output} = err ->
        if output =~ "is already" do
          :ok
        else
          err
        end
    end
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
        # "-p", "28083:18083",
        "--name",
        @container_name,
        image,
        "bash",
        "-c",
        "echo $EMQX_NODE_NAME > nodename ; tail -f /dev/null"
      ]
    )
  end

  def stop_container() do
    Logger.info(%{msg: "starting_container"})
    {:ok, _} = run("docker", ["rm", "-f", @container_name])
    Logger.info(%{msg: "container_stopped"})
  end

  def run_in_container(cmd) do
    cmd =
      cmd
      |> List.wrap()
      |> Enum.join(" ; ")

    run("docker", ["exec", @container_name, "bash", "-c", cmd])
  end

  def run(command, args) do
    {out, exit_code} = System.cmd(command, args)

    if exit_code != 0 do
      {:error, exit_code, out}
    else
      {:ok, out}
    end
  end

  def main() do
    Logger.info(%{msg: "starting_container"})
    image = System.fetch_env!("EMQX_IMAGE")

    list_test_configs()
    |> Enum.each(fn emqx44_backup_path ->
      Logger.info(%{msg: "running_test_case", input_path: emqx44_backup_path})
      {:ok, _} = start_container(image)
      {:ok, converted_path} = convert!(emqx44_backup_path)
      :ok = import!(converted_path)
      Logger.info(%{msg: "test_case_succeeded", input_path: emqx44_backup_path})
      stop_container()
    end)
  end
end

Test.ConvertAndLoad.main()
