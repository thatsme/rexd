missing = Enum.reject(Rexd.Test.Oracle.tools(), &Rexd.Test.Oracle.available?/1)

for tool <- missing do
  IO.warn("#{tool} not found on PATH: skipping oracle tests tagged :#{tool}", [])
end

ExUnit.start(exclude: missing)
