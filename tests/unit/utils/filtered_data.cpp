#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <utils/filtered_data.h>

TEST(FilteredData, construct)
{
    EXPECT_NO_THROW(NST::utils::FilteredData());
}
