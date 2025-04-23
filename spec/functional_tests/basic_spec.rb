# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Basic Run', type: :aruba do
  before(:all) do
    @binary_path = File.expand_path('../../aether', __dir__)
  end

  def run_and_expect_success(args, output: /Usage:/)
    run_command("#{@binary_path} #{args}")
    expect(last_command_started).to have_output(output)
    expect(last_command_started).to be_successfully_executed
  end

  it 'prints the help' do
    run_and_expect_success('-h')
  end

  it 'prints the help url mode' do
    run_and_expect_success('help url')
  end

  it 'returns an error for unknown commands' do
    run_command("#{@binary_path} invalid-command")
    expect(last_command_started).to have_output(/unknown command/i)
    expect(last_command_started).not_to be_successfully_executed
  end

  it 'shows version information' do
    run_and_expect_success('--version', output: /version/i)
  end

  it 'shows error for missing required argument' do
    run_command("#{@binary_path} url")
    expect(last_command_started).to have_output(/required/i)
    expect(last_command_started).not_to be_successfully_executed
  end
end
