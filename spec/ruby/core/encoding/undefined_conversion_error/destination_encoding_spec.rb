require_relative "../../../spec_helper"
require_relative '../fixtures/classes'

describe "Encoding::UndefinedConversionError#destination_encoding" do
  before :each do
    @exception = EncodingSpecs::UndefinedConversionError.exception
  end

  it "returns an Encoding object" do
    @exception.destination_encoding.should be_an_instance_of(Encoding)
  end

  it "is equal to the destination encoding of the object that raised it" do
    @exception.destination_encoding.should == Encoding::US_ASCII
  end
end
