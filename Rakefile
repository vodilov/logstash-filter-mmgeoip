require 'jars/installer'
task :install_jars do
  ENV['JARS_HOME'] = Dir.pwd + "/vendor/jar-dependencies/runtime-jars"
  ENV['JARS_VENDOR'] = "false"
  Jars::Installer.new.vendor_jars!(false)
end

