# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'testphp.vulnweb.com', type: :aruba do
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

  it 'listproducts.php - cat param' do
    run_and_expect_success('http://testphp.vulnweb.com/listproducts.php?cat=')
  end

  it 'listproducts.php - artist param' do
    run_and_expect_success('http://testphp.vulnweb.com/listproducts.php?artist=')
  end

  it 'hpp - pp param' do
    run_and_expect_success('http://testphp.vulnweb.com/hpp/?pp=')
  end

  it 'params.php - p param' do
    run_and_expect_success('http://testphp.vulnweb.com/hpp/params.php?p=')
  end

  it 'search.php - searchFor body param (POST)' do
    run_and_expect_success('http://testphp.vulnweb.com/search.php', data: 'searchFor=', method: 'POST')
  end

  it 'guestbook.php - name body param (POST)' do
    run_and_expect_success('http://testphp.vulnweb.com/guestbook.php', data: 'name=', method: 'POST')
  end

  it 'guestbook.php - name param (GET)' do
    run_and_expect_success('http://testphp.vulnweb.com/guestbook.php?name=')
  end

  it 'test for SQLi param' do
    run_and_expect_success('http://testphp.vulnweb.com/listproducts.php?cat=1%27%20OR%201=1--')
  end

  it 'test for XSS param' do
    run_and_expect_success('http://testphp.vulnweb.com/listproducts.php?cat=<script>alert(1)</script>', output: /<script>alert\(1\)<\/script>/)
  end
end
