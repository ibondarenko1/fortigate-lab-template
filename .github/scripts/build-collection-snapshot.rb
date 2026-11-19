#!/usr/bin/env ruby
# Build a dependency-submission snapshot from the pinned Ansible collections.

require "json"
require "time"
require "uri"
require "yaml"
MANIFEST = "automation/requirements.yml"
GALAXY_NAME = /\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/
VERSION = /\A[A-Za-z0-9._+~-]+\z/
COMMIT = /\A[0-9a-f]{40}\z/
GITHUB_REPOSITORY_URL = %r{\Ahttps://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\.git\z}
output = ARGV.fetch(0) { abort "usage: #{File.basename($PROGRAM_NAME)} OUTPUT" }
abort "usage: #{File.basename($PROGRAM_NAME)} OUTPUT" unless ARGV.length == 1
begin
  document = YAML.safe_load(File.read(MANIFEST), permitted_classes: [], aliases: false)
rescue Psych::Exception, SystemCallError => error
  abort "Cannot read #{MANIFEST}: #{error.message}"
end
abort "#{MANIFEST} must contain only a collections array" unless document.is_a?(Hash) && document.keys == ["collections"] && document["collections"].is_a?(Array)
abort "#{MANIFEST} must contain at least one collection" if document["collections"].empty?
resolved = {}
document["collections"].each do |entry|
  abort "Each collection entry must be a mapping" unless entry.is_a?(Hash)
  name, type, version = entry.values_at("name", "type", "version")
  abort "Collection entries require a pinned version" unless name.is_a?(String) && version.is_a?(String) && !version.empty? && version.match?(VERSION)
  keys = entry.keys.sort
  package_url, metadata = if keys == ["name", "version"]
    abort "Galaxy collection #{name.inspect} has an invalid name" unless name.match?(GALAXY_NAME)
    ["pkg:generic/#{name}@#{version}", {}]
  elsif keys == ["name", "type", "version"] && type == "git"
    match = GITHUB_REPOSITORY_URL.match(name)
    abort "Git collection #{name.inspect} must be a clean HTTPS GitHub URL" unless match
    abort "Git collection #{name.inspect} must be pinned to a commit SHA" unless version.match?(COMMIT)
    ["pkg:github/#{match[1]}/#{match[2]}@#{version}", {"source_url" => name, "pinned_commit" => version}]
  elsif type && type != "git"
    abort "Unsupported collection source type #{type.inspect} for #{name.inspect}"
  else
    abort "Unsupported collection entry for #{name.inspect}"
  end
  abort "Duplicate package URL #{package_url}" if resolved.key?(package_url)
  resolved[package_url] = {
    "package_url" => package_url,
    "metadata" => metadata,
    "relationship" => "direct",
    "scope" => "runtime",
    "dependencies" => []
  }
end
repository = ENV.fetch("GITHUB_REPOSITORY") { abort "GITHUB_REPOSITORY is not set" }
sha = ENV.fetch("GITHUB_SHA") { abort "GITHUB_SHA is not set" }
ref = ENV.fetch("GITHUB_REF") { abort "GITHUB_REF is not set" }
run_id = ENV.fetch("GITHUB_RUN_ID") { abort "GITHUB_RUN_ID is not set" }
server = ENV.fetch("GITHUB_SERVER_URL", "https://github.com").sub(%r{/+\z}, "")
snapshot = {
  "version" => 0,
  "job" => {"id" => run_id, "correlator" => "fortigate-ansible-collections", "html_url" => "#{server}/#{repository}/actions/runs/#{run_id}"},
  "sha" => sha,
  "ref" => ref,
  "detector" => {"name" => "FortiGate Lab Ansible collection manifest", "version" => "1.0.0", "url" => "#{server}/#{repository}/blob/#{sha}/#{MANIFEST}"},
  "scanned" => Time.now.utc.iso8601,
  "manifests" => {MANIFEST => {"name" => MANIFEST, "file" => {"source_location" => MANIFEST}, "resolved" => resolved}}
}
File.write(output, JSON.generate(snapshot) + "\n")
