require_relative '../../spec_helper'
require_relative 'fixtures/classes'
require_relative 'shared/iterable_and_tolerating_size_increasing'
require_relative '../enumerable/shared/enumeratorized'

describe "Array#sort_by!" do
  it "sorts array in place by passing each element to the given block" do
    a = [-100, -2, 1, 200, 30000]
    a.sort_by!{ |e| e.to_s.size }
    a.should == [1, -2, 200, -100, 30000]
  end

  it "returns an Enumerator if not given a block" do
    (1..10).to_a.sort_by!.should be_an_instance_of(Enumerator)
  end

  it "completes when supplied a block that always returns the same result" do
    a = [2, 3, 5, 1, 4]
    a.sort_by!{  1 }
    a.should be_an_instance_of(Array)
    a.sort_by!{  0 }
    a.should be_an_instance_of(Array)
    a.sort_by!{ -1 }
    a.should be_an_instance_of(Array)
  end

  it "raises a FrozenError on a frozen array" do
    -> { ArraySpecs.frozen_array.sort_by! {}}.should raise_error(FrozenError)
  end

  it "raises a FrozenError on an empty frozen array" do
    -> { ArraySpecs.empty_frozen_array.sort_by! {}}.should raise_error(FrozenError)
  end

  it "raises a FrozenError on a frozen array only during iteration if called without a block" do
    enum = ArraySpecs.frozen_array.sort_by!
    -> { enum.each {} }.should raise_error(FrozenError)
  end

  it "returns the specified value when it would break in the given block" do
    [1, 2, 3].sort_by!{ break :a }.should == :a
  end

  it "makes some modification even if finished sorting when it would break in the given block" do
    partially_sorted = (1..5).map{|i|
      ary = [5, 4, 3, 2, 1]
      ary.sort_by!{|x,y| break if x==i; x<=>y}
      ary
    }
    partially_sorted.any?{|ary| ary != [1, 2, 3, 4, 5]}.should be_true
  end

  it "changes nothing when called on a single element array" do
    [1].sort_by!(&:to_s).should == [1]
  end

  it "does not truncate the array is the block raises an exception" do
    a = [1, 2, 3]
    begin
      a.sort_by! { raise StandardError, 'Oops' }
    rescue
    end

    a.should == [1, 2, 3]
  end

  it "doesn't change array if error is raised" do
    a = [4, 3, 2, 1]
    begin
      a.sort_by! do |e|
        raise StandardError, 'Oops' if e == 1
        e
      end
    rescue StandardError
    end

    a.should == [4, 3, 2, 1]
  end

  it_behaves_like :enumeratorized_with_origin_size, :sort_by!, [1,2,3]
end

describe "Array#sort_by!" do
  it_behaves_like :array_iterable_and_tolerating_size_increasing, :sort_by!
end
