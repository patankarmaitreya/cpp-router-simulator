#include <gtest/gtest.h>

#include <vector>
#include <cstdint>

#include "core/byte_utils.hpp"

TEST(ByteUtilsTest, ReadsU16BigEndian) {
    // Arrange
    const std::vector<uint8_t> buffer = {
        0x08, 0x00
    };

    // Act
    const auto value = read_u16_be(buffer, 0);

    // Assert
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0x0800);
}

TEST(ByteUtilsTest, ReadsU16BigEndianAtOffset) {
    // Arrange
    const std::vector<uint8_t> buffer = {
        0xaa, 0xbb, 0x08, 0x06
    };

    // Act
    const auto value = read_u16_be(buffer, 2);

    // Assert
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0x0806);
}

TEST(ByteUtilsTest, ReadsU32BigEndian) {
    // Arrange
    const std::vector<uint8_t> buffer = {
        0xc0, 0xa8, 0x01, 0x0a
    };

    // Act
    const auto value = read_u32_be(buffer, 0);

    // Assert
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0xc0a8010a);
}

TEST(ByteUtilsTest, ReadsU32BigEndianAtOffset) {
    // Arrange
    const std::vector<uint8_t> buffer = {
        0xff, 0xff, 0x0a, 0x00, 0x01, 0x02
    };

    // Act
    const auto value = read_u32_be(buffer, 2);

    // Assert
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 0x0a000102);
}

TEST(ByteUtilsTest, ReadU16FailsWhenOffsetIsOutOfBounds) {
    // Arrange
    const std::vector<uint8_t> buffer = {
        0x08
    };

    // Act
    const auto value = read_u16_be(buffer, 1);

    // Assert
    EXPECT_FALSE(value.has_value());
}

TEST(ByteUtilsTest, ReadU16FailsWhenOffsetLeavesOnlyOneByte) {
    // Arrange
    const std::vector<uint8_t> buffer = {
        0xaa, 0xbb, 0xcc
    };

    // Act
    const auto value = read_u16_be(buffer, 2);

    // Assert
    EXPECT_FALSE(value.has_value());
}

TEST(ByteUtilsTest, ReadU32FailsWhenOffsetIsOutOfBounds) {
    // Arrange
    const std::vector<uint8_t> buffer = {
        0xc0, 0xa8, 0x01
    };

    // Act
    const auto value = read_u32_be(buffer, 3);

    // Assert
    EXPECT_FALSE(value.has_value());
}

TEST(ByteUtilsTest, ReadU32FailsWhenOffsetLeavesFewerThanFourBytes) {
    // Arrange
    const std::vector<uint8_t> buffer = {
        0xaa, 0xbb, 0xc0, 0xa8, 0x01
    };

    // Act
    const auto value = read_u32_be(buffer, 2);

    // Assert
    EXPECT_FALSE(value.has_value());
}

TEST(ByteUtilsTest, WritesU16BigEndian) {
    // Arrange
    std::vector<uint8_t> buffer = {
        0x00, 0x00
    };

    // Act
    const bool success = write_u16_be(buffer, 0, 0x0800);

    // Assert
    ASSERT_TRUE(success);
    ASSERT_EQ(buffer.size(), 2);

    EXPECT_EQ(buffer[0], 0x08);
    EXPECT_EQ(buffer[1], 0x00);
}

TEST(ByteUtilsTest, WritesU16BigEndianAtOffset) {
    // Arrange
    std::vector<uint8_t> buffer = {
        0xaa, 0xbb, 0x00, 0x00
    };

    // Act
    const bool success = write_u16_be(buffer, 2, 0x0806);

    // Assert
    ASSERT_TRUE(success);
    ASSERT_EQ(buffer.size(), 4);

    EXPECT_EQ(buffer[0], 0xaa);
    EXPECT_EQ(buffer[1], 0xbb);
    EXPECT_EQ(buffer[2], 0x08);
    EXPECT_EQ(buffer[3], 0x06);
}

TEST(ByteUtilsTest, WriteU16FailsWhenOffsetLeavesOnlyOneByte) {
    // Arrange
    std::vector<uint8_t> buffer = {
        0xaa, 0xbb, 0x00
    };

    // Act
    const bool success = write_u16_be(buffer, 2, 0x0800);

    // Assert
    EXPECT_FALSE(success);
}

TEST(ByteUtilsTest, WritesU32BigEndian) {
    // Arrange
    std::vector<uint8_t> buffer = {
        0x00, 0x00, 0x00, 0x00
    };

    // Act
    const bool success = write_u32_be(buffer, 0, 0xc0a8010a);

    // Assert
    ASSERT_TRUE(success);
    ASSERT_EQ(buffer.size(), 4);

    EXPECT_EQ(buffer[0], 0xc0);
    EXPECT_EQ(buffer[1], 0xa8);
    EXPECT_EQ(buffer[2], 0x01);
    EXPECT_EQ(buffer[3], 0x0a);
}

TEST(ByteUtilsTest, WritesU32BigEndianAtOffset) {
    // Arrange
    std::vector<uint8_t> buffer = {
        0xaa, 0xbb, 0x00, 0x00, 0x00, 0x00
    };

    // Act
    const bool success = write_u32_be(buffer, 2, 0x0a000102);

    // Assert
    ASSERT_TRUE(success);
    ASSERT_EQ(buffer.size(), 6);

    EXPECT_EQ(buffer[0], 0xaa);
    EXPECT_EQ(buffer[1], 0xbb);
    EXPECT_EQ(buffer[2], 0x0a);
    EXPECT_EQ(buffer[3], 0x00);
    EXPECT_EQ(buffer[4], 0x01);
    EXPECT_EQ(buffer[5], 0x02);
}

TEST(ByteUtilsTest, WriteU32FailsWhenOffsetLeavesFewerThanFourBytes) {
    // Arrange
    std::vector<uint8_t> buffer = {
        0xaa, 0xbb, 0x00, 0x00, 0x00
    };

    // Act
    const bool success = write_u32_be(buffer, 2, 0xc0a8010a);

    // Assert
    EXPECT_FALSE(success);
}