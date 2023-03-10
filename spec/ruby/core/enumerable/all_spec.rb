require_relative '../../spec_helper'
require_relative 'fixtures/classes'

describe "Enumerable#all?" do
  before :each do
    @enum = EnumerableSpecs::Numerous.new
    @empty = EnumerableSpecs::Empty.new()
    @enum1 = EnumerableSpecs::Numerous.new(0, 1, 2, -1)
    @enum2 = EnumerableSpecs::Numerous.new(nil, false, true)
  end

  it "always returns true on empty enumeration" do
    @empty.should.all?
    @empty.all? { nil }.should == true

    [].should.all?
    [].all? { false }.should == true

    {}.should.all?
    {}.all? { nil }.should == true
  end

  it "raises an ArgumentError when more than 1 argument is provided" do
    -> { @enum.all?(1, 2, 3) }.should raise_error(ArgumentError)
    -> { [].all?(1, 2, 3) }.should raise_error(ArgumentError)
    -> { {}.all?(1, 2, 3) }.should raise_error(ArgumentError)
  end

  it "does not hide exceptions out of #each" do
    -> {
      EnumerableSpecs::ThrowingEach.new.all?
    }.should raise_error(RuntimeError)

    -> {
      EnumerableSpecs::ThrowingEach.new.all? { false }
    }.should raise_error(RuntimeError)
  end

  describe "with no block" do
    it "returns true if no elements are false or nil" do
      @enum.should.all?
      @enum1.should.all?
      @enum2.should_not.all?

      EnumerableSpecs::Numerous.new('a','b','c').should.all?
      EnumerableSpecs::Numerous.new(0, "x", true).should.all?
    end

    it "returns false if there are false or nil elements" do
      EnumerableSpecs::Numerous.new(false).should_not.all?
      EnumerableSpecs::Numerous.new(false, false).should_not.all?

      EnumerableSpecs::Numerous.new(nil).should_not.all?
      EnumerableSpecs::Numerous.new(nil, nil).should_not.all?

      EnumerableSpecs::Numerous.new(1, nil, 2).should_not.all?
      EnumerableSpecs::Numerous.new(0, "x", false, true).should_not.all?
      @enum2.should_not.all?
    end

    it "gathers whole arrays as elements when each yields multiple" do
      multi = EnumerableSpecs::YieldsMultiWithFalse.new
      multi.all?.should be_true
    end
  end

  describe "with block" do
    it "returns true if the block never returns false or nil" do
      @enum.all? { true }.should == true
      @enum1.all?{ |o| o < 5 }.should == true
      @enum1.all?{ |o| 5 }.should == true
    end

    it "returns false if the block ever returns false or nil" do
      @enum.all? { false }.should == false
      @enum.all? { nil }.should == false
      @enum1.all?{ |o| o > 2 }.should == false

      EnumerableSpecs::Numerous.new.all? { |i| i > 5 }.should == false
      EnumerableSpecs::Numerous.new.all? { |i| i == 3 ? nil : true }.should == false
    end

    it "stops iterating once the return value is determined" do
      yielded = []
      EnumerableSpecs::Numerous.new(:one, :two, :three).all? do |e|
        yielded << e
        false
      end.should == false
      yielded.should == [:one]

      yielded = []
      EnumerableSpecs::Numerous.new(true, true, false, true).all? do |e|
        yielded << e
        e
      end.should == false
      yielded.should == [true, true, false]

      yielded = []
      EnumerableSpecs::Numerous.new(1, 2, 3, 4, 5).all? do |e|
        yielded << e
        e
      end.should == true
      yielded.should == [1, 2, 3, 4, 5]
    end

    it "does not hide exceptions out of the block" do
      -> {
        @enum.all? { raise "from block" }
      }.should raise_error(RuntimeError)
    end

    it "gathers initial args as elements when each yields multiple" do
      multi = EnumerableSpecs::YieldsMulti.new
      yielded = []
      multi.all? { |e| yielded << e }.should == true
      yielded.should == [1, 3, 6]
    end

    it "yields multiple arguments when each yields multiple" do
      multi = EnumerableSpecs::YieldsMulti.new
      yielded = []
      multi.all? { |*args| yielded << args }.should == true
      yielded.should == [[1, 2], [3, 4, 5], [6, 7, 8, 9]]
    end
  end

  describe 'when given a pattern argument' do
    it "calls `===` on the pattern the return value " do
      pattern = EnumerableSpecs::Pattern.new { |x| x >= 0 }
      @enum1.all?(pattern).should == false
      pattern.yielded.should == [[0], [1], [2], [-1]]
    end

    it "always returns true on empty enumeration" do
      @empty.all?(Integer).should == true
      [].all?(Integer).should == true
      {}.all?(NilClass).should == true
    end

    it "does not hide exceptions out of #each" do
      -> {
        EnumerableSpecs::ThrowingEach.new.all?(Integer)
      }.should raise_error(RuntimeError)
    end

    it "returns true if the pattern never returns false or nil" do
      pattern = EnumerableSpecs::Pattern.new { |x| 42 }
      @enum.all?(pattern).should == true

      [1, 42, 3].all?(pattern).should == true

      pattern = EnumerableSpecs::Pattern.new { |x| Array === x }
      {a: 1, b: 2}.all?(pattern).should == true
    end

    it "returns false if the pattern ever returns false or nil" do
      pattern = EnumerableSpecs::Pattern.new { |x| x >= 0 }
      @enum1.all?(pattern).should == false
      pattern.yielded.should == [[0], [1], [2], [-1]]

      [1, 2, 3, -1].all?(pattern).should == false

      pattern = EnumerableSpecs::Pattern.new { |x| x[1] >= 0 }
      {a: 1, b: -1}.all?(pattern).should == false
    end

    it "does not hide exceptions out of pattern#===" do
      pattern = EnumerableSpecs::Pattern.new { raise "from pattern" }
      -> {
        @enum.all?(pattern)
      }.should raise_error(RuntimeError)
    end

    it "calls the pattern with gathered array when yielded with multiple arguments" do
      multi = EnumerableSpecs::YieldsMulti.new
      pattern = EnumerableSpecs::Pattern.new { true }
      multi.all?(pattern).should == true
      pattern.yielded.should == [[[1, 2]], [[3, 4, 5]], [[6, 7, 8, 9]]]
    end

    it "ignores the block if there is an argument" do
      -> {
        EnumerableSpecs::Numerous.new(1, 2, 3, 4, 5).all?(String) { true }.should == false
      }.should complain(/given block not used/)
    end
  end
end
