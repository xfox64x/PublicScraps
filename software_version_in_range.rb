#!/usr/bin/env ruby

# I still suck at Ruby.
# Here's a series of functions to check if the rough idea of a software version falls within
# a range or matches other operator criteria (e.g. 1.1.1.1 < VERSION <= 5.0.69.420).
# See examples at bottom.

def normalize_version_strings(first_string, second_string)
  if first_string.nil? || second_string.nil? || first_string.empty? || second_string.empty?
    return first_string, second_string
  end
  first_groups = first_string.split(".").length
  second_groups = second_string.split(".").length
  if first_groups != second_groups
    if first_groups > second_groups
      ((1..first_groups-second_groups).to_a).each do |digit|
        second_string += ".0"
      end
    end
    if first_groups < second_groups
      ((1..second_groups-first_groups).to_a).each do |digit|
        first_string += ".0"
      end
    end
  end
  return first_string, second_string
end

def version_compare(first_version, second_version)
  # return greater_than, less_than, equal, not_equal
  if first_version.nil? || second_version.nil? || first_version.empty? || second_version.empty?
    return false, false, false, false
  end
  first_version, second_version = normalize_version_strings(first_version, second_version)
  first_version.split(".").zip(second_version.split(".")).each do |first_value, second_value|
    #print first_value.to_s+" "+second_value.to_s+"\n"
    if first_value.to_i > second_value.to_i
      return true, false, false, true
    elsif first_value.to_i < second_value.to_i
      return false, true, false, true
    end
  end
  return false, false, true, false
end

def version_conditional(left_operand, right_operand, condition)
  if left_operand.nil? || right_operand.nil? || condition.nil? || left_operand.empty? || right_operand.empty? || condition.empty?
    return 
  end
  greater_than, less_than, equal, not_equal = version_compare(left_operand, right_operand)
  if greater_than == false && less_than == false && equal == false && not_equal == false
    return
  end
  if condition == ">"
    return greater_than
  elsif condition == ">="
    return greater_than || equal
  elsif condition == "<"
    return less_than
  elsif condition == "<="
    return less_than || equal
  elsif condition == "=="
    return equal
  elsif condition == "!="
    return not_equal
  end
end

def version_within_range(range_string, version_string)
  if range_string.nil? || version_string.nil? || range_string.empty? || version_string.empty?
    return false
  end
  
  match_object = range_string.match /((?<first_bound>((\d+\.)|(\d+))+)\s*(?<first_operator>((\<)|(\<=)|(\>=)|(\>)|(==)|(!=)))\s*)?VERSION(\s*(?<second_operator>((\<)|(\<=)|(\>=)|(\>)|(==)|(!=)))\s*(?<second_bound>((\d+\.)|(\d+))+))?/
  first_bound = match_object[:first_bound]
  first_operator = match_object[:first_operator]
  second_bound = match_object[:second_bound]
  second_operator = match_object[:second_operator]

  if !first_bound.nil? && !first_operator.nil? && !first_bound.empty? && !first_operator.empty?
    left_side_judgement = version_conditional(first_bound, version_string, first_operator)  
  end

  if !second_bound.nil? && !second_operator.nil? && !second_bound.empty? && !second_operator.empty?
    right_side_judgement = version_conditional(version_string, second_bound, second_operator)  
  end

  if !left_side_judgement.nil? && !right_side_judgement.nil?
    return (left_side_judgement && right_side_judgement)
  elsif !left_side_judgement.nil?
    return left_side_judgement
  else
    return right_side_judgement
  end
end

print version_within_range("1.0.0<=VERSION <= 5", "2.1").to_s+"\n"
print version_within_range("1.0.0 <= VERSION<=5", "6.1").to_s+"\n"
print version_within_range("1.0.0 <= VERSION<=5", "0.9").to_s+"\n"
print version_within_range("1.0.0<=VERSION <= 5", "1.0").to_s+"\n"
print version_within_range("1.0.0<=VERSION<=5", "5.0").to_s+"\n"

print "\n"
print version_within_range("1.0.0 <  VERSION <= 5", "2.1").to_s+"\n"
print version_within_range("1.0.0 < VERSION <= 5", "6.1").to_s+"\n"
print version_within_range("1.0.0 < VERSION <=    5", "0.9").to_s+"\n"
print version_within_range("1.0.0 < VERSION<=    5", "1.0").to_s+"\n"
print version_within_range("1.0.0<VERSION     <=5", "5.0").to_s+"\n"

print "\n"
print version_within_range("1.0.0 <= VERSION < 5", "2.1").to_s+"\n"
print version_within_range("1.0.0 <= VERSION < 5", "6.1").to_s+"\n"
print version_within_range("1.0.0 <= VERSION < 5", "0.9").to_s+"\n"
print version_within_range("1.0.0 <= VERSION < 5", "1.0").to_s+"\n"
print version_within_range("1.0.0 <= VERSION < 5", "5.0").to_s+"\n"

print "\n"
print version_within_range("1.0.0 < VERSION < 5", "2.1").to_s+"\n"
print version_within_range("1.0.0 < VERSION < 5", "6.1").to_s+"\n"
print version_within_range("1.0.0 < VERSION < 5", "0.9").to_s+"\n"
print version_within_range("1.0.0 < VERSION < 5", "1.0").to_s+"\n"
print version_within_range("1.0.0 < VERSION < 5", "5.0").to_s+"\n"

print "\n"
print version_within_range("1.0.0 < VERSION", "2.1").to_s+"\n"
print version_within_range("1.0.0 < VERSION", "0.9").to_s+"\n"
print version_within_range("1.0.0 <= VERSION", "2.1").to_s+"\n"
print version_within_range("1.0.0 <= VERSION", "0.9").to_s+"\n"
print version_within_range("1.0.0 <= VERSION", "1").to_s+"\n"
print version_within_range("1.0.0 < VERSION", "1").to_s+"\n"

print "\n"
print version_within_range("VERSION < 5", "2.1").to_s+"\n"
print version_within_range("VERSION < 5", "6.1").to_s+"\n"
print version_within_range("VERSION <= 5", "2.1").to_s+"\n"
print version_within_range("VERSION <= 5", "6.1").to_s+"\n"
print version_within_range("VERSION < 5", "5").to_s+"\n"
print version_within_range("VERSION <= 5", "5").to_s+"\n"

print "\n"
print version_within_range("VERSION == 5.1.1", "5.1.1").to_s+"\n"
print version_within_range("VERSION != 5.1.1", "5.1.1").to_s+"\n"
print version_within_range("VERSION == 5.1.1", "5").to_s+"\n"
print version_within_range("VERSION != 5.1.1", "5").to_s+"\n"

print "\n"
print version_within_range("1 < VERSION == 5.1.1", "5.1.1").to_s+"\n"
print version_within_range("6 < VERSION != 5.1.1", "5.1.1").to_s+"\n"
print version_within_range("1 < VERSION == 5.1.1", "5").to_s+"\n"
print version_within_range("6 < VERSION != 5.1.1", "5").to_s+"\n"
