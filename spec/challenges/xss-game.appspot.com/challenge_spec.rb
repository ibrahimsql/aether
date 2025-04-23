# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'xss-game.appspot.com', type: :aruba do
  before(:all) do
    @binary_path = File.expand_path('../../../aether', __dir__)
  end

  def run_and_expect_success(url, data: nil, method: nil, output: /\[V\]/)
    cmd = "#{@binary_path} url '#{url}'"
    cmd += " -d '#{data}'" if data
    cmd += " -X #{method}" if method
    run_command(cmd)
    expect(last_command_started).to have_output(output)
    expect(last_command_started).to be_successfully_executed
  end

  it 'level1 - reflected XSS' do
    run_and_expect_success('https://xss-game.appspot.com/level1/frame?query=<script>alert(1)</script>', output: /<script>alert\(1\)<\/script>/)
  end

  it 'level2 - DOM Based XSS (should warn if not detected)' do
    run_and_expect_success('https://xss-game.appspot.com/level2/frame?query=<img src=x onerror=alert(2)>', output: /\[V\]/)
  end

  it 'level3 - Fragment Based XSS (should warn if not detected)' do
    run_and_expect_success('https://xss-game.appspot.com/level3/frame?query=#<svg onload=alert(3)>', output: /\[V\]/)
  end
end