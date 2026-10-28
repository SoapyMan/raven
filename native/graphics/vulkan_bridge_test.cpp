#include "vulkan_bridge.h"
#include "nt/providers.h"

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/mman.h>

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

int main(int argc, char **argv)
{
	try {
		check(argc == 3, "bootstrap and Vulkan fixture required");
		std::ifstream file(argv[2], std::ios::binary | std::ios::ate);
		check(file && file.tellg() > 0 && file.tellg() <= 1024 * 1024, "cannot read Vulkan fixture");
		std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
		file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()))), "truncated Vulkan fixture");
		raven::ModuleSet modules;
		const auto base = raven::PEImage(bytes).image_base;
		auto &entry = modules.add("client.exe", std::move(bytes), base);
		const auto executed = raven::run_native_process(modules, entry, argv[1], std::chrono::seconds(5));
		check(executed.stop == raven::NativeStop::returned && executed.value == 0, "compiled Vulkan workflow failed");
		const auto field = [&]<typename T>(const std::string &name) {
			T value{};
			const auto offset = modules.resolve({"client.exe", name, 0, false, 0}) - base;
			const auto data = entry.loaded.data().subspan(offset, sizeof(T));
			std::memcpy(&value, data.data(), sizeof(T));
			return value;
		};
		uint32_t version = 0;
		check(vkEnumerateInstanceVersion(&version) == VK_SUCCESS && version == field.template operator()<uint32_t>("loader_version"), "guest loader version differs from host");
		VkApplicationInfo application{};
		application.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
		application.apiVersion = VK_API_VERSION_1_1;
		VkInstanceCreateInfo info{};
		info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
		info.pApplicationInfo = &application;
		VkInstance reference = VK_NULL_HANDLE;
		check(vkCreateInstance(&info, nullptr, &reference) == VK_SUCCESS, "host reference instance failed");
		VkPhysicalDeviceProperties expected{};
		uint32_t count = 0;
		const auto count_status = vkEnumeratePhysicalDevices(reference, &count, nullptr);
		std::vector<VkPhysicalDevice> devices(count);
		const auto devices_status = vkEnumeratePhysicalDevices(reference, &count, devices.data());
		if (count_status == VK_SUCCESS && devices_status == VK_SUCCESS && count)
			vkGetPhysicalDeviceProperties(devices[0], &expected);
		VkPhysicalDeviceMemoryProperties expected_memory{};
		VkPhysicalDeviceFeatures expected_features{};
		std::vector<VkQueueFamilyProperties> expected_families;
		if (count) {
			vkGetPhysicalDeviceMemoryProperties(devices[0], &expected_memory);
			vkGetPhysicalDeviceFeatures(devices[0], &expected_features);
			uint32_t family_total = 0;
			vkGetPhysicalDeviceQueueFamilyProperties(devices[0], &family_total, nullptr);
			expected_families.resize(family_total);
			vkGetPhysicalDeviceQueueFamilyProperties(devices[0], &family_total, expected_families.data());
		}
		vkDestroyInstance(reference, nullptr);
		check(count_status == VK_SUCCESS && devices_status == VK_SUCCESS && count == field.template operator()<uint32_t>("device_count"), "guest physical device count differs from host");
		const auto observed = field.template operator()<VkPhysicalDeviceProperties>("observed");
		check(observed.apiVersion == expected.apiVersion && observed.vendorID == expected.vendorID &&
			observed.deviceID == expected.deviceID && observed.deviceType == expected.deviceType &&
			std::strcmp(observed.deviceName, expected.deviceName) == 0 &&
			observed.limits.maxImageDimension2D == expected.limits.maxImageDimension2D &&
			observed.limits.maxMemoryAllocationCount == expected.limits.maxMemoryAllocationCount,
			"guest physical device properties differ from host");
		const auto families = field.template operator()<std::array<VkQueueFamilyProperties, 16>>("families");
		check(field.template operator()<uint32_t>("family_count") == expected_families.size() && !expected_families.empty(), "guest queue family count differs from host");
		for (size_t index = 0; index < expected_families.size(); ++index)
			check(families[index].queueFlags == expected_families[index].queueFlags && families[index].queueCount == expected_families[index].queueCount &&
				families[index].timestampValidBits == expected_families[index].timestampValidBits, "guest queue family differs from host");
		const auto memory_observed = field.template operator()<VkPhysicalDeviceMemoryProperties>("memory_properties");
		check(memory_observed.memoryTypeCount == expected_memory.memoryTypeCount && memory_observed.memoryHeapCount == expected_memory.memoryHeapCount &&
			std::memcmp(memory_observed.memoryTypes, expected_memory.memoryTypes, sizeof(expected_memory.memoryTypes)) == 0 &&
			std::memcmp(memory_observed.memoryHeaps, expected_memory.memoryHeaps, sizeof(expected_memory.memoryHeaps)) == 0, "guest memory properties differ from host");
		const auto features_observed = field.template operator()<VkPhysicalDeviceFeatures>("features");
		check(std::memcmp(&features_observed, &expected_features, sizeof(expected_features)) == 0, "guest device features differ from host");
		check(field.template operator()<uint32_t>("copy_workflow") == 1 && field.template operator()<uint32_t>("copy_fence_waits") == 1, "guest buffer copy through the device did not complete");
		const auto copied = field.template operator()<std::array<uint8_t, 256>>("copied");
		for (size_t index = 0; index < copied.size(); ++index)
			check(copied[index] == uint8_t(index * 7 + 3), "device copied different bytes than the guest wrote");
		check(field.template operator()<uint32_t>("compute_workflow") == 1, "guest compute dispatch did not complete");
		const auto computed = field.template operator()<std::array<uint32_t, 64>>("computed");
		for (uint32_t index = 0; index < computed.size(); ++index)
			check(computed[index] == (index + 10) * 3 + index, "compute shader produced different values than the specification");
		check(field.template operator()<uint32_t>("image_workflow") == 1, "guest image round trip did not complete");
		const auto readback = field.template operator()<std::array<uint32_t, 64>>("image_readback");
		for (uint32_t index = 0; index < readback.size(); ++index)
			check(readback[index] == (0xff000000u | (index * 3u << 16) | (index * 2u << 8) | index), "image round trip returned different texels");
		check(field.template operator()<uint32_t>("extension_workflow") == 1, "guest extension and query workflow did not complete");
		{
			// Chained feature and property queries must match what the driver reports for the same device.
			VkPhysicalDeviceVulkan11Features host11{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_1_FEATURES};
			VkPhysicalDeviceVulkan12Features host12{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES};
			VkPhysicalDeviceVulkan13Features host13{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES};
			VkPhysicalDeviceVulkan12Properties host_properties12{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_PROPERTIES};
			host11.pNext = &host12; host12.pNext = &host13;
			VkPhysicalDeviceFeatures2 features2{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2, &host11};
			VkPhysicalDeviceProperties2 properties2{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, &host_properties12};
			VkInstanceCreateInfo reference_info{};
			reference_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
			reference_info.pApplicationInfo = &application;
			VkInstance query_instance = VK_NULL_HANDLE;
			check(vkCreateInstance(&reference_info, nullptr, &query_instance) == VK_SUCCESS, "host query instance failed");
			uint32_t query_count = 1;
			VkPhysicalDevice query_device = VK_NULL_HANDLE;
			vkEnumeratePhysicalDevices(query_instance, &query_count, &query_device);
			vkGetPhysicalDeviceFeatures2(query_device, &features2);
			vkGetPhysicalDeviceProperties2(query_device, &properties2);
			VkFormatProperties format_reference{};
			vkGetPhysicalDeviceFormatProperties(query_device, VK_FORMAT_R8G8B8A8_UNORM, &format_reference);
			VkImageFormatProperties image_reference{};
			vkGetPhysicalDeviceImageFormatProperties(query_device, VK_FORMAT_R8G8B8A8_UNORM, VK_IMAGE_TYPE_2D, VK_IMAGE_TILING_OPTIMAL,
				VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT, 0, &image_reference);
			vkDestroyInstance(query_instance, nullptr);
			const auto features11 = field.template operator()<VkPhysicalDeviceVulkan11Features>("features11");
			const auto features12 = field.template operator()<VkPhysicalDeviceVulkan12Features>("features12");
			const auto features13 = field.template operator()<VkPhysicalDeviceVulkan13Features>("features13");
			check(std::memcmp(reinterpret_cast<const char *>(&features11) + 16, reinterpret_cast<const char *>(&host11) + 16, sizeof(host11) - 16) == 0 &&
				std::memcmp(reinterpret_cast<const char *>(&features12) + 16, reinterpret_cast<const char *>(&host12) + 16, sizeof(host12) - 16) == 0 &&
				std::memcmp(reinterpret_cast<const char *>(&features13) + 16, reinterpret_cast<const char *>(&host13) + 16, sizeof(host13) - 16) == 0,
				"chained feature structures differ from the host");
			const auto guest_properties12 = field.template operator()<VkPhysicalDeviceVulkan12Properties>("properties12");
			check(guest_properties12.driverID == host_properties12.driverID && std::strcmp(guest_properties12.driverName, host_properties12.driverName) == 0 &&
				guest_properties12.maxUpdateAfterBindDescriptorsInAllPools == host_properties12.maxUpdateAfterBindDescriptorsInAllPools,
				"chained Vulkan 1.2 properties differ from the host");
			const auto format_one = field.template operator()<VkFormatProperties>("format_one");
			const auto format_two = field.template operator()<VkFormatProperties>("format_two");
			check(format_one.optimalTilingFeatures == format_reference.optimalTilingFeatures && format_two.optimalTilingFeatures == format_reference.optimalTilingFeatures &&
				format_two.linearTilingFeatures == format_reference.linearTilingFeatures, "format properties differ from the host");
			const auto image_format = field.template operator()<VkImageFormatProperties>("image_format");
			check(image_format.maxExtent.width == image_reference.maxExtent.width && image_format.maxMipLevels == image_reference.maxMipLevels &&
				image_format.sampleCounts == image_reference.sampleCounts, "image format properties differ from the host");
		}
		check(field.template operator()<uint32_t>("graphics_workflow") == 1, "guest render pass did not complete");
		const auto rendered = field.template operator()<std::array<uint32_t, 256>>("rendered");
		for (uint32_t y = 0; y < 16; ++y)
			for (uint32_t x = 0; x < 16; ++x) {
				// The triangle covers the pixels whose centres satisfy x + y < 16; the rest keeps the blue clear colour.
				const double centre_x = x + 0.5, centre_y = y + 0.5;
				if (centre_x + centre_y < 15.5 || centre_x + centre_y > 16.5)
					check(rendered[y * 16 + x] == (centre_x + centre_y < 16 ? 0xff0000ffu : 0xffff0000u), "rendered pixel differs from the triangle coverage");
			}
		check(field.template operator()<uint32_t>("textured_workflow") == 1, "guest textured quad did not complete");
		const auto textured = field.template operator()<std::array<uint32_t, 256>>("textured");
		for (uint32_t y = 0; y < 16; ++y)
			for (uint32_t x = 0; x < 16; ++x) {
				// Nearest sampling over a full-target quad: each 8x8 quadrant shows one texel (red, green, blue, white).
				if ((x % 8) >= 2 && (x % 8) <= 5 && (y % 8) >= 2 && (y % 8) <= 5) {
					static const uint32_t expected[4] = {0xff0000ffu, 0xff00ff00u, 0xffff0000u, 0xffffffffu};
					check(textured[y * 16 + x] == expected[(y / 8) * 2 + x / 8], "textured pixel differs from the sampled texel");
				}
			}
		check(field.template operator()<uint32_t>("device_workflow") == 1, "guest logical device workflow did not complete");
		std::vector<raven::LoadedImage *> images;
		for (const auto &[name, module] : modules.all())
			images.push_back(&module->loaded);
		raven::NativeProcess process(images, argv[1], std::chrono::seconds(2));
		raven::VulkanBridge bridge(process, modules);
		for (const auto &symbol : modules.all().at("vulkan-1.dll")->exports)
			process.add_api_trap(raven::api_trap_address(*modules.all().at("vulkan-1.dll"), "vulkan-1.dll", symbol.names.front(), symbol.address));
		const auto memory = process.map_memory(4096, PROT_READ | PROT_WRITE);
		const auto rejected = [&](const std::string &name, std::span<const uint64_t> arguments) {
			const auto address = modules.resolve({"vulkan-1.dll", name, 0, false, 0});
			check(process.call(address, arguments, std::chrono::seconds(2)).stop == raven::NativeStop::api, "Vulkan negative test did not stop");
			bool failed = false;
			try { bridge.dispatch(name); } catch (const std::runtime_error &) { failed = true; }
			check(failed, "invalid Vulkan guest operation returned apparent success");
			process.return_api(0);
			check(process.resume(std::chrono::seconds(2)).stop == raven::NativeStop::returned, "negative Vulkan test did not restore guest caller");
		};
		const uint64_t forged[] = {0x1234, memory};
		rejected("vkGetPhysicalDeviceProperties", forged);
		const uint64_t bad_string[] = {0, UINT64_MAX};
		rejected("vkGetInstanceProcAddr", bad_string);
		process.write_memory(memory, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&info), sizeof(info)));
		const uint64_t allocator[] = {memory, 1, memory + 256};
		rejected("vkCreateInstance", allocator);
		const uint64_t bad_output[] = {memory, 0, UINT64_MAX};
		rejected("vkCreateInstance", bad_output);
		// Logical devices: forged handles, allocators and unimplemented create-info fields all fail before reaching the driver.
		const uint64_t forged_device[] = {0x4321, 0, 0, memory};
		rejected("vkGetDeviceQueue", forged_device);
		const uint64_t forged_wait[] = {0x4321};
		rejected("vkDeviceWaitIdle", forged_wait);
		const uint64_t forged_create[] = {0x1234, memory, 0, memory + 512};
		rejected("vkCreateDevice", forged_create);
		const uint64_t forged_proc[] = {0x4321, memory};
		rejected("vkGetDeviceProcAddr", forged_proc);
		const uint64_t forged_buffer[] = {0x4321, 0x7777, memory, 0};
		rejected("vkCreateBuffer", forged_buffer);
		const uint64_t forged_submit[] = {0x4321, 1, memory, 0};
		rejected("vkQueueSubmit", forged_submit);
		const uint64_t forged_queue[] = {0x4321};
		rejected("vkQueueWaitIdle", forged_queue);
		const uint64_t forged_map[] = {0x4321, 0x7777, 0, 4096, 0, memory};
		rejected("vkMapMemory", forged_map);
		const uint64_t forged_pipeline[] = {0x7777, 1, 0x1234};
		rejected("vkCmdBindPipeline", forged_pipeline);
		const uint64_t forged_shader[] = {0x4321, memory, 0, memory + 512};
		rejected("vkCreateShaderModule", forged_shader);
		const uint64_t forged_dispatch[] = {0x7777, 1, 1, 1};
		rejected("vkCmdDispatch", forged_dispatch);
		const uint64_t forged_image[] = {0x4321, memory, 0, memory + 512};
		rejected("vkCreateImage", forged_image);
		const uint64_t forged_barrier[] = {0x7777, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		rejected("vkCmdPipelineBarrier", forged_barrier);
		const uint64_t forged_semaphore[] = {0x4321, memory, 0, memory + 512};
		rejected("vkCreateSemaphore", forged_semaphore);
		const uint64_t forged_pass[] = {0x7777, memory, 0};
		rejected("vkCmdBeginRenderPass", forged_pass);
		const uint64_t forged_draw[] = {0x7777, 3, 1, 0, 0};
		rejected("vkCmdDraw", forged_draw);
		const uint64_t forged_framebuffer[] = {0x4321, memory, 0, memory + 512};
		rejected("vkCreateFramebuffer", forged_framebuffer);
		const uint64_t forged_vertex[] = {0x7777, 0, 1, memory, memory};
		rejected("vkCmdBindVertexBuffers", forged_vertex);
		const uint64_t forged_index[] = {0x7777, 0x1234, 0, 0};
		rejected("vkCmdBindIndexBuffer", forged_index);
		const uint64_t forged_sampler[] = {0x4321, memory, 0, memory + 512};
		rejected("vkCreateSampler", forged_sampler);
		const uint64_t forged_viewport[] = {0x7777, 0, 1, memory};
		rejected("vkCmdSetViewport", forged_viewport);
		const uint64_t forged_features2[] = {0x1234, memory};
		rejected("vkGetPhysicalDeviceFeatures2", forged_features2);
		const uint64_t forged_query[] = {0x1234, memory, memory};
		for (const char *name : {"vkGetPhysicalDeviceFeatures2KHR", "vkGetPhysicalDeviceProperties2KHR", "vkGetPhysicalDeviceMemoryProperties2KHR",
			"vkGetPhysicalDeviceFormatProperties2KHR", "vkGetPhysicalDeviceQueueFamilyProperties2KHR"})
			rejected(name, forged_query);
		const uint64_t forged_extensions[] = {0x1234, 0, memory, 0};
		rejected("vkEnumerateDeviceExtensionProperties", forged_extensions);
		const uint64_t forged_format[] = {0x1234, 37, memory};
		rejected("vkGetPhysicalDeviceFormatProperties", forged_format);
		const uint64_t forged_command[] = {0x7777, memory};
		rejected("vkBeginCommandBuffer", forged_command);
		process.unmap_memory(memory);
		std::cout << "Guest Vulkan instance, logical device, queues, memory and feature queries, stable physical handles, zero-capacity enumeration and checked negatives match host " << expected.deviceName << '\n';
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
