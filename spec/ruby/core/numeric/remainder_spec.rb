require_relative '../../spec_helper'
require_relative 'fixtures/classes'

describe "Numeric#remainder" do
  before :each do
    @obj    = NumericSpecs::Subclass.new
    @result = mock("Numeric#% result")
    @other  = mock("Passed Object")
    ruby_version_is "3.3" do
      @other.should_receive(:coerce).with(@obj).and_return([@obj, @other])
    end
  end

  it "returns the result of calling self#% with other if self is 0" do
    @obj.should_receive(:%).with(@other).and_return(@result)
    @result.should_receive(:==).with(0).and_return(true)

    @obj.remainder(@other).should equal(@result)
  end

  it "returns the result of calling self#% with other if self and other are greater than 0" do
    @obj.should_receive(:%).with(@other).and_return(@result)
    @result.should_receive(:==).with(0).and_return(false)

    @obj.should_receive(:<).with(0).and_return(false)

    @obj.should_receive(:>).with(0).and_return(true)
    @other.should_receive(:<).with(0).and_return(false)

    @obj.remainder(@other).should equal(@result)
  end

  it "returns the result of calling self#% with other if self and other are less than 0" do
    @obj.should_receive(:%).with(@other).and_return(@result)
    @result.should_receive(:==).with(0).and_return(false)

    @obj.should_receive(:<).with(0).and_return(true)
    @other.should_receive(:>).with(0).and_return(false)

    @obj.should_receive(:>).with(0).and_return(false)

    @obj.remainder(@other).should equal(@result)
  end

  it "returns the result of calling self#% with other - other if self is greater than 0 and other is less than 0" do
    @obj.should_receive(:%).with(@other).and_return(@result)
    @result.should_receive(:==).with(0).and_return(false)

    @obj.should_receive(:<).with(0).and_return(false)

    @obj.should_receive(:>).with(0).and_return(true)
    @other.should_receive(:<).with(0).and_return(true)

    @result.should_receive(:-).with(@other).and_return(:result)

    @obj.remainder(@other).should == :result
  end

  it "returns the result of calling self#% with other - other if self is less than 0 and other is greater than 0" do
    @obj.should_receive(:%).with(@other).and_return(@result)
    @result.should_receive(:==).with(0).and_return(false)

    @obj.should_receive(:<).with(0).and_return(true)
    @other.should_receive(:>).with(0).and_return(true)

    @result.should_receive(:-).with(@other).and_return(:result)

    @obj.remainder(@other).should == :result
  end
end
