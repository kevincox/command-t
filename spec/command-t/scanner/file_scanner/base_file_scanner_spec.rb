# Copyright 2010-present Greg Hurrell. All rights reserved.
# Licensed under the terms of the BSD 2-clause license.

require 'spec_helper'

[
  CommandT::Scanner::FileScanner::FindFileScanner,
  CommandT::Scanner::FileScanner::GitFileScanner,
  CommandT::Scanner::FileScanner::RubyFileScanner,
  CommandT::Scanner::FileScanner::WatchmanFileScanner,
].each do |klass|
  describe klass do
    before do
      @dir = File.join(File.dirname(__FILE__), '..', '..', '..', '..', 'fixtures')
      @all_fixtures = %w(
        bar/abc bar/xyz baz bing foo/alpha/t1 foo/alpha/t2 foo/beta
      )
      @all_fixtures << ".hidden/file" if klass == CommandT::Scanner::FileScanner::GitFileScanner
      @scanner = klass.new(@dir)

      stub(::VIM).evaluate(/exists/) { 1 }
      stub(::VIM).evaluate(/expand\(.+\)/) { '0' }
      stub(::VIM).command(/echon/)
      stub(::VIM).command('redraw')
    end

    describe 'paths method' do
      it 'returns a list of regular files' do
        expect(@scanner.paths.to_a).to match_array(@all_fixtures)
      end
    end

    describe 'path= method' do
      it 'allows repeated applications of scanner at different paths' do
        expect(@scanner.paths.to_a).to match_array(@all_fixtures)

        # drill down 1 level
        @scanner.path = File.join(@dir, 'foo')
        expect(@scanner.paths.to_a).to match_array(%w(alpha/t1 alpha/t2 beta))

        # and another
        @scanner.path = File.join(@dir, 'foo', 'alpha')
        expect(@scanner.paths.to_a).to match_array(%w(t1 t2))
      end
    end

    describe "'wildignore' exclusion" do
      context "when there is a 'wildignore' setting in effect" do
        it "filters out matching files" do
          scanner =
            klass.new @dir,
              :wildignore => CommandT::VIM::wildignore_to_regexp('xyz')
          expect(scanner.paths.to_a.count).to eq(@all_fixtures.count - 1)
        end
      end

      context "when there is no 'wildignore' setting in effect" do
        it "does nothing" do
          scanner = klass.new @dir
          expect(scanner.paths.to_a.count).to eq(@all_fixtures.count)
        end
      end
    end

    describe "hidden file exclusion" do
      next if klass == CommandT::Scanner::FileScanner::GitFileScanner

      it "excludes hidden files by default" do
        expect(@scanner.paths.to_a).to match_array(@all_fixtures)
      end

      it "includes hidden files when told" do
        scanner = klass.new @dir, scan_dot_directories: true
        expect(scanner.paths.to_a).to match_array(@all_fixtures + %w(.hidden/file))
      end
    end

    describe ':max_depth option' do
      next if klass == CommandT::Scanner::FileScanner::GitFileScanner

      it 'does not descend below "max_depth" levels' do
        @scanner = klass.new @dir, :max_depth => 1
        expect(@scanner.paths.to_a).to match_array(%w(bar/abc bar/xyz baz bing foo/beta))
      end
    end
  end
end
