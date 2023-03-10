require_relative '../../spec_helper'
require_relative 'fixtures/classes'

describe "Enumerable#any?" do
  before :each do
    @enum = EnumerableSpecs::Numerous.new
    @empty = EnumerableSpecs::Empty.new
    @enum1 = EnumerableSpecs::Numerous.new(0, 1, 2, -1)
    @enum2 = EnumerableSpecs::Numerous.new(nil, false, true)
  end

  it "always returns false on empty enumeration" do
    @empty.should_not.any?
    @empty.any? { nil }.should == false

    [].should_not.any?
    [].any? { false }.should == false

    {}.should_not.any?
    {}.any? { nil }.should == false
  end

  it "raises an ArgumentError when more than 1 argument is provided" do
    -> { @enum.any?(1, 2, 3) }.should raise_error(ArgumentError)
    -> { [].any?(1, 2, 3) }.should raise_error(ArgumentError)
    -> { {}.any?(1, 2, 3) }.should raise_error(ArgumentError)
  end

  it "does not hide exceptions out of #each" do
    -> {
      EnumerableSpecs::ThrowingEach.new.any?
    }.should raise_error(RuntimeError)

    -> {
      EnumerableSpecs::ThrowingEach.new.any? { false }
    }.should raise_error(RuntimeError)
  end

  describe "with no block" do
    it "returns true if any element is not false or nil" do
      @enum.should.any?
      @enum1.should.any?
      @enum2.should.any?
      EnumerableSpecs::Numerous.new(true).should.any?
      EnumerableSpecs::Numerous.new('a','b','c').should.any?
      EnumerableSpecs::Numerous.new('a','b','c', nil).should.any?
      EnumerableSpecs::Numerous.new(1, nil, 2).should.any?
      EnumerableSpecs::Numerous.new(1, false).should.any?
      EnumerableSpecs::Numerous.new(false, nil, 1, false).should.any?
      EnumerableSpecs::Numerous.new(false, 0, nil).should.any?
    end

    it "returns false if all elements are false or nil" do
      EnumerableSpecs::Numerous.new(false).should_not.any?
      EnumerableSpecs::Numerous.new(false, false).should_not.any?
      EnumerableSpecs::Numerous.new(nil).should_not.any?
      EnumerableSpecs::Numerous.new(nil, nil).should_not.any?
      EnumerableSpecs::Numerous.new(nil, false, nil).should_not.any?
    end

    it "gathers whole arrays as elements when each yields multiple" do
      multi = EnumerableSpecs::YieldsMultiWithFalse.new
      multi.any?.should be_true
    end
  end

  describe "with block" do
    it "returns true if the block ever returns other than false or nil" do
      @enum.any? { true }.should == true
      @enum.any? { 0 }.should == true
      @enum.any? { 1 }.should == true

      @enum1.any? { Object.new }.should == true
      @enum1.any?{ |o| o < 1 }.should == true
      @enum1.any?{ |o| 5 }.should == true

      @enum2.any? { |i| i == nil }.should == true
    end

    it "returns false if the block never returns other than false or nil" do
      @enum.any? { false }.should == false
      @enum.any? { nil }.should == false

      @enum1.any?{ |o| o < -10 }.should == false
      @enum1.any?{ |o| nil }.should == false

      @enum2.any? { |i| i == :stuff }.should == false
    end

    it "stops iterating once the return value is determined" do
      yielded = []
      EnumerableSpecs::Numerous.new(:one, :two, :three).any? do |e|
        yielded << e
        false
      end.should == false
      yielded.should == [:one, :two, :three]

      yielded = []
      EnumerableSpecs::Numerous.new(true, true, false, true).any? do |e|
        yielded << e
        e
      end.should == true
      yielded.should == [true]

      yielded = []
      EnumerableSpecs::Numerous.new(false, nil, false, true, false).any? do |e|
        yielded << e
        e
      end.should == true
      yielded.should == [false, nil, false, true]

      yielded = []
      EnumerableSpecs::Numerous.new(1, 2, 3, 4, 5).any? do |e|
        yielded << e
        e
      end.should == true
      yielded.should == [1]
    end

    it "does not hide exceptions out of the block" do
      -> {
        @enum.any? { raise "from block" }
      }.should raise_error(RuntimeError)
    end

    it "gathers initial args as elements when each yields multiple" do
      multi = EnumerableSpecs::YieldsMulti.new
      yielded = []
      multi.any? { |e| yielded << e; false }.should == false
      yielded.should == [1, 3, 6]
    end

    it "yields multiple arguments when each yields multiple" do
      multi = EnumerableSpecs::YieldsMulti.new
      yielded = []
      multi.any? { |*args| yielded << args; false }.should == false
      yielded.should == [[1, 2], [3, 4, 5], [6, 7, 8, 9]]
    end
  end

  describe 'when given a pattern argument' do
    it "calls `===` on the pattern the return value " do
      pattern = EnumerableSpecs::Pattern.new { |x| x == 2 }
      @enum1.any?(pattern).should == true
      pattern.yielded.should == [[0], [1], [2]]
    end

    it "always returns false on empty enumeration" do
      @empty.any?(Integer).should == false
      [].any?(Integer).should == false
      {}.any?(NilClass).should == false
    end

    it "does not hide exceptions out of #each" do
      -> {
        EnumerableSpecs::ThrowingEach.new.any?(Integer)
      }.should raise_error(RuntimeError)
    end

    it "returns true if the pattern ever returns a truthy value" do
      @enum2.any?(NilClass).should == true
      pattern = EnumerableSpecs::Pattern.new { |x| 42 }
      @enum.any?(pattern).should == true

      [1, 42, 3].any?(pattern).should == true

      pattern = EnumerableSpecs::Pattern.new { |x| x == [:b, 2] }
      {a: 1, b: 2}.any?(pattern).should == true
    end

    it "returns false if the block never returns other than false or nil" do
      pattern = EnumerableSpecs::Pattern.new { |x| nil }
      @enum1.any?(pattern).should == false
      pattern.yielded.should == [[0], [1], [2], [-1]]

      [1, 2, 3].any?(pattern).should == false
      {a: 1}.any?(pattern).should == false
    end

    it "does not hide exceptions out of pattern#===" do
      pattern = EnumerableSpecs::Pattern.new { raise "from pattern" }
      -> {
        @enum.any?(pattern)
      }.should raise_error(RuntimeError)
    end

    it "calls the pattern with gathered array when yielded with multiple arguments" do
      multi = EnumerableSpecs::YieldsMulti.new
      pattern = EnumerableSpecs::Pattern.new { false }
      multi.any?(pattern).should == false
      pattern.yielded.should == [[[1, 2]], [[3, 4, 5]], [[6, 7, 8, 9]]]
    end

    it "ignores the block if there is an argument" do
      -> {
        EnumerableSpecs::Numerous.new(1, 2, 3, 4, 5).any?(String) { true }.should == false
      }.should complain(/given block not used/)
    end
  end
end
